# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** is a technique that allows attackers to **bypass Active Directory authentication** by **injecting a master password** into the LSASS process of each domain controller. After injection, the master password (default **`mimikatz`**) can be used to authenticate as **any domain user** while their real passwords still work.<sup>[[1]](#references)[[2]](#references)</sup>

Key facts:

- Requires **Domain Admin/SYSTEM + SeDebugPrivilege** on every DC and must be **reapplied after each reboot**.<sup>[[2]](#references)</sup>
- The classic Mimikatz implementation patches **NTLM** and **Kerberos RC4 (etype 0x17)** validation paths; AES-only authentication does **not accept that skeleton password through the RC4 hook**.<sup>[[2]](#references)</sup>
- Can conflict with third‑party LSA authentication packages or additional smart‑card / MFA providers.<sup>[[2]](#references)</sup>
- The Mimikatz module accepts the optional switch `/letaes` to avoid touching Kerberos/AES hooks in case of compatibility issues.<sup>[[3]](#references)</sup>

### Execution

Classic, non‑PPL protected LSASS:

```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

If **LSASS is running as a protected process light (PPL)**, user-mode debug access is blocked. The historical Mimikatz procedure below loads its kernel driver and removes protection before patching LSASS. Credential Guard is a separate isolation control and should not be used as a synonym for PPL.<sup>[[3]](#references)[[4]](#references)</sup>

```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```

After injection, authenticate with any domain account but use password `mimikatz` (or the value set by the operator). Remember to repeat on **all DCs** in multi‑DC environments.

## Mitigations

- **Log monitoring**
  - System **Event ID 7045** (service/driver install) for unsigned drivers such as `mimidrv.sys`.
  - **Sysmon**: Event ID 7 (driver load) for `mimidrv.sys`; Event ID 10 for suspicious access to `lsass.exe` from non‑system processes.
  - Security **Event ID 4673/4611** for sensitive privilege use or LSA authentication package registration anomalies; correlate with unexpected 4624 logons using RC4 (etype 0x17) from DCs.
- **Hardening LSASS**
  - Keep **RunAsPPL** and **Credential Guard** enabled where supported. They provide different protections, and together raise the cost and telemetry of attempts to modify or extract LSASS secrets.<sup>[[4]](#references)</sup>
  - Disable legacy **RC4** where possible; Kerberos tickets limited to AES prevent the RC4 hook path used by the skeleton key.<sup>[[2]](#references)</sup>
- Quick PowerShell hunts:
  - Detect unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
  - Hunt for Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
  - Validate PPL is enforced after reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

For additional credential‑hardening guidance check [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

{{#include ../../banners/hacktricks-training.md}}
