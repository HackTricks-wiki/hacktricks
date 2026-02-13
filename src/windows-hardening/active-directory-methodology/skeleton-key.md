# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** is a technique that allows attackers to **bypass Active Directory authentication** by **injecting a master password** into the LSASS process of each domain controller. After injection, the master password (default **`mimikatz`**) can be used to authenticate as **any domain user** while their real passwords still work.

Key facts:

- Requires **Domain Admin/SYSTEM + SeDebugPrivilege** on every DC and must be **reapplied after each reboot**.
- Patches **NTLM** and **Kerberos RC4 (etype 0x17)** validation paths; AES-only realms or accounts enforcing AES will **not accept the skeleton key**.
- Can conflict with third‑party LSA authentication packages or additional smart‑card / MFA providers.
- The Mimikatz module accepts the optional switch `/letaes` to avoid touching Kerberos/AES hooks in case of compatibility issues.

### Execution

Classic, non‑PPL protected LSASS:

```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

If **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), a kernel driver is needed to remove protection before patching LSASS:

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
  - Keep **RunAsPPL/Credential Guard/Secure LSASS** enabled on DCs to force attackers into kernel‑mode driver deployment (more telemetry, harder exploitation).
  - Disable legacy **RC4** where possible; Kerberos tickets limited to AES prevent the RC4 hook path used by the skeleton key.
- Quick PowerShell hunts:
  - Detect unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
  - Hunt for Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
  - Validate PPL is enforced after reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

For additional credential‑hardening guidance check [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
