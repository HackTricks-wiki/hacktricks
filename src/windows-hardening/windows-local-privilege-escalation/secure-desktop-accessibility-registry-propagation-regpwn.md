# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Accessibility features persist user configuration under HKCU and propagate it into per-session HKLM locations. During a **Secure Desktop** transition (lock screen or UAC prompt), **SYSTEM** components re-copy these values. If the **per-session HKLM key is writable by the user**, it becomes a privileged write choke point that can be redirected with **registry symbolic links**, yielding an **arbitrary SYSTEM registry write**.

The RegPwn technique abuses that propagation chain with a small race window stabilized via an **opportunistic lock (oplock)** on a file used by `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Example feature: **On-Screen Keyboard** (`osk`). The relevant locations are:

- **System-wide feature list**:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
  - `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
  - `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation during a secure desktop transition (simplified):

1. **User `atbroker.exe`** copies `HKCU\...\ATConfig\osk` to `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** copies `HKLM\...\Session<session id>\ATConfig\osk` to `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** copies `HKU\.DEFAULT\...\ATConfig\osk` back to `HKLM\...\Session<session id>\ATConfig\osk`.

If the session HKLM subtree is writable by the user, step 2/3 provide a SYSTEM write through a location the user can replace.

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Replace the user-writable per-session key with a **registry symbolic link** that points to an attacker-chosen destination. When the SYSTEM copy occurs, it follows the link and writes attacker-controlled values into the arbitrary target key.

Key idea:

- Victim write target (user-writable):
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker replaces that key with a **registry link** to any other key.
- SYSTEM performs the copy and writes into the attacker-chosen key with SYSTEM permissions.

This yields an **arbitrary SYSTEM registry write** primitive.

## Winning the Race Window with Oplocks

There is a short timing window between **SYSTEM `osk.exe`** starting and writing the per-session key. To make it reliable, the exploit places an **oplock** on:

```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```

When the oplock triggers, the attacker swaps the per-session HKLM key for a registry link, lets the SYSTEM write land, then removes the link.

## Example Exploitation Flow (High Level)

1. Get current **session ID** from the access token.
2. Start a hidden `osk.exe` instance and sleep briefly (ensure the oplock will trigger).
3. Write attacker-controlled values to:
   - `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Set an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Trigger **Secure Desktop** (`LockWorkstation()`), causing SYSTEM `atbroker.exe` / `osk.exe` to start.
6. On oplock trigger, replace `HKLM\...\Session<session id>\ATConfig\osk` with a **registry link** to an arbitrary target.
7. Wait briefly for the SYSTEM copy to complete, then remove the link.

## Converting the Primitive to SYSTEM Execution

One straightforward chain is to overwrite a **service configuration** value (e.g., `ImagePath`) and then start the service. The RegPwn PoC overwrites the `ImagePath` of **`msiserver`** and triggers it by instantiating the **MSI COM object**, resulting in **SYSTEM** code execution.

## Related

For other Secure Desktop / UIAccess behaviors, see:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
