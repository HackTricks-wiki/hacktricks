# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) are DLL-based security packages loaded by the Local Security Authority (LSA). Windows registers custom SSP/AP DLLs through the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` `REG_MULTI_SZ` value and loads registered packages when the system starts.<sup>[[1]](#references)</sup>

Because SSPs run in LSA and can receive credentials, adversaries may abuse a malicious package for credential access and persistence. MITRE tracks this behavior as T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz includes `mimilib.dll`, which implements an SSP that records credentials handled after it is loaded. In an authorized lab, place the DLL that matches the target architecture in `C:\Windows\System32`, then inspect the current package list before changing it.<sup>[[2]](#references)[[3]](#references)</sup>

```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```

A typical existing value can contain packages such as `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`, and `pku2u`. Preserve every existing entry when adding the custom package.<sup>[[1]](#references)</sup>

Append `mimilib` without replacing the existing packages:

```powershell
if ($packages -notcontains 'mimilib') {
    Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```

After a reboot, the package is loaded into LSA and subsequent captured credentials are written to `C:\Windows\System32\kiwissp.log` by this implementation.<sup>[[2]](#references)[[3]](#references)</sup>

## In-memory Loading

Mimikatz can also inject its SSP implementation into the current LSASS process:<sup>[[3]](#references)</sup>

```text
privilege::debug
misc::memssp
```

This method does not persist across a reboot.<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

Monitor changes to `...\Lsa\Security Packages` and unexpected DLL loads into `lsass.exe`. Security event 4657 records a registry **value** modification only when the relevant Audit Registry policy and SACL are configured.<sup>[[2]](#references)[[4]](#references)</sup>

Where compatible, enable added LSA protection and investigate unsigned or unexpected SSP DLLs. Microsoft documents LSA protection specifically as a control against code injection that could compromise credentials.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registering SSP/AP DLLs](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

{{#include ../../banners/hacktricks-training.md}}
