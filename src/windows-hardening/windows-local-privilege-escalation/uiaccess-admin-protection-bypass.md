# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo exposes `RAiLaunchAdminProcess` to spawn UIAccess processes (intended for accessibility). UIAccess bypasses most User Interface Privilege Isolation (UIPI) message filtering so accessibility software can drive higher-IL UI.
- Enabling UIAccess directly requires `NtSetInformationToken(TokenUIAccess)` with **SeTcbPrivilege**, so low-priv callers rely on the service. The service performs three checks on the target binary before setting UIAccess:
- Embedded manifest contains `uiAccess="true"`.
- Signed by any certificate trusted by the Local Machine root store (no EKU/Microsoft requirement).
- Located in an administrator-only path on the system drive (e.g., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluding specific writable subpaths).
- `RAiLaunchAdminProcess` performs no consent prompt for UIAccess launches (otherwise accessibility tooling could not drive the prompt).

## Token shaping and integrity levels
- If the checks succeed, AppInfo **copies the caller token**, enables UIAccess, and bumps Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL increased by **+16 levels** up to a **High** cap (System IL is never assigned).
- If the caller token already has UIAccess, IL is left unchanged.
- “Ratchet” trick: a UIAccess process can disable UIAccess on itself, relaunch via `RAiLaunchAdminProcess`, and gain another +16 IL increment. Medium➜High takes 255 relaunches (noisy, but works).

## Why UIAccess enables an Admin Protection escape
- UIAccess lets a lower-IL process send window messages to higher-IL windows (bypassing UIPI filters). At **equal IL**, classic UI primitives like `SetWindowsHookEx` **do allow code injection/DLL loading** into any process that owns a window (including **message-only windows** used by COM).
- Admin Protection launches the UIAccess process under the **limited user’s identity** but at **High IL**, silently. Once arbitrary code runs inside that High-IL UIAccess process, the attacker can inject into other High-IL processes on the desktop (even belonging to different users), breaking the intended separation.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolves the supplied path via `GetFinalPathNameByHandle` and then applies **string allow/deny checks** against hardcoded roots/exclusions. Multiple bypass classes stem from that simplistic validation:
- **Directory named streams**: Excluded writable directories (e.g., `C:\Windows\tracing`) can be bypassed with a named stream on the directory itself, e.g. `C:\Windows\tracing:file.exe`. The string checks see `C:\Windows\` and miss the excluded subpath.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` does **not require a `.exe` extension**. Overwriting any writable file under an allowed root with an executable payload works, or copying a signed `uiAccess="true"` EXE into any writable subdirectory (e.g., update leftovers such as `Tasks_Migrated` when present) lets it pass the secure-path check.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins could install signed MSIX packages that landed in `WindowsApps`, which was not excluded. Packaging a UIAccess binary inside the MSIX then launching it via `RAiLaunchAdminProcess` yielded a **promptless High-IL UIAccess process**. Microsoft mitigated by excluding this path; the `uiAccess` restricted MSIX capability itself already requires admin install.

## Attack workflow (High IL without a prompt)
1. Obtain/build a **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Place it where AppInfo’s allowlist accepts it (or abuse a path-validation edge case/writable artifact as above).
3. Call `RAiLaunchAdminProcess` to spawn it **silently** with UIAccess + elevated IL.
4. From that High-IL foothold, target another High-IL process on the desktop using **window hooks/DLL injection** or other same-IL primitives to fully compromise the admin context.

## Enumerating candidate writable paths
Run the PowerShell helper to discover writable/overwritable objects inside nominally secure roots from the perspective of a chosen token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Daha geniş görünürlük için Yönetici olarak çalıştır; token’ın erişimini yansıtmak için `-ProcessId`'i düşük ayrıcalıklı bir işleme ayarla.
- Adayları `RAiLaunchAdminProcess` ile kullanmadan önce bilinen yasak alt dizinleri hariç tutmak için manuel filtre uygula.

## Referanslar
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
