# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo exposes the internal `RAiLaunchAdminProcess` path used to start UIAccess applications for accessibility. UIAccess permits selected interaction across User Interface Privilege Isolation (UIPI) boundaries; it is not a general bypass of every process-security boundary.<sup>[[1]](#references)[[3]](#references)</sup>
- Enabling UIAccess directly requires `NtSetInformationToken(TokenUIAccess)` with **SeTcbPrivilege**, so low-priv callers rely on the service. The service performs three checks on the target binary before setting UIAccess:
  - Embedded manifest contains `uiAccess="true"`.
  - Signed by any certificate trusted by the Local Machine root store (no EKU/Microsoft requirement).
  - Located in an administrator-only path on the system drive (e.g., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluding specific writable subpaths).
- `RAiLaunchAdminProcess` performs no consent prompt for UIAccess launches (otherwise accessibility tooling could not drive the prompt).<sup>[[1]](#references)</sup>

## Token shaping and integrity levels
- If the checks succeed, AppInfo **copies the caller token**, enables UIAccess, and bumps Integrity Level (IL):
  - Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
  - Non-admin user ➜ IL increased by **+16 levels** up to a **High** cap (System IL is never assigned).
  - If the caller token already has UIAccess, IL is left unchanged.
- “Ratchet” trick: a UIAccess process can disable UIAccess on itself, relaunch via `RAiLaunchAdminProcess`, and gain another +16 IL increment. Medium➜High takes 255 relaunches (noisy, but works).<sup>[[1]](#references)</sup>

## Why UIAccess enables an Admin Protection escape
- UIAccess lets a lower-IL process send window messages to higher-IL windows (bypassing UIPI filters). At **equal IL**, classic UI primitives like `SetWindowsHookEx` **do allow code injection/DLL loading** into any process that owns a window (including **message-only windows** used by COM). 
- Admin Protection launches the UIAccess process under the **limited user’s identity** but at **High IL**, silently. Once arbitrary code runs inside that High-IL UIAccess process, the attacker can inject into other High-IL processes on the desktop (even belonging to different users), breaking the intended separation.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- On Windows 10 1803+ the API moved into Win32k (`NtUserGetWindowProcessHandle`) and can open a process handle using a caller-supplied `DesiredAccess`. The kernel path uses `ObOpenObjectByPointer(..., KernelMode, ...)`, which bypasses normal user-mode access checks.<sup>[[2]](#references)</sup>
- Preconditions in practice: the target window must be on the same desktop, and UIPI checks must pass. Historically, a caller with UIAccess could bypass UIPI failure and still get a kernel-mode handle (fixed as CVE-2023-41772).
- Historical impact: a window handle became a **capability** for process access such as `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, or `PROCESS_VM_OPERATION` that the caller could not normally obtain. Before the documented fixes, this could cross sandbox and protected-process boundaries when a target exposed a window, including a message-only window.<sup>[[2]](#references)</sup>
- Practical abuse flow: enumerate or locate HWNDs (e.g., `EnumWindows`/`FindWindowEx`), resolve the owning PID (`GetWindowThreadProcessId`), call `GetProcessHandleFromHwnd`, then use the returned handle for memory read/write or code-hijack primitives.
- Post-fix behavior: UIAccess no longer grants kernel-mode opens on UIPI failure and allowed access rights are restricted to the legacy hook set; Windows 11 24H2 adds process-protection checks and feature-flagged safer paths. Disabling UIPI system-wide (`EnforceUIPI=0`) weakens these protections.<sup>[[2]](#references)</sup>

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolves the supplied path via `GetFinalPathNameByHandle` and then applies **string allow/deny checks** against hardcoded roots/exclusions. Multiple bypass classes stem from that simplistic validation:
- **Directory named streams**: Excluded writable directories (e.g., `C:\Windows\tracing`) can be bypassed with a named stream on the directory itself, e.g. `C:\Windows\tracing:file.exe`. The string checks see `C:\Windows\` and miss the excluded subpath.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` does **not require a `.exe` extension**. Overwriting any writable file under an allowed root with an executable payload works, or copying a signed `uiAccess="true"` EXE into any writable subdirectory (e.g., update leftovers such as `Tasks_Migrated` when present) lets it pass the secure-path check.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins could install signed MSIX packages that landed in `WindowsApps`, which was not excluded. Packaging a UIAccess binary inside the MSIX then launching it via `RAiLaunchAdminProcess` yielded a **promptless High-IL UIAccess process**. Microsoft mitigated by excluding this path; the `uiAccess` restricted MSIX capability itself already requires admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL without a prompt)
1. Obtain/build a **signed UIAccess binary** (manifest `uiAccess="true"`). For a realistic assessment, test with trust material and paths explicitly authorized for the lab; do not add an attacker certificate to a production machine's Local Machine root store.
2. Place it where AppInfo’s allowlist accepts it (or abuse a path-validation edge case/writable artifact as above).
3. Call `RAiLaunchAdminProcess` to spawn it **silently** with UIAccess + elevated IL.
4. From that High-IL foothold, target another High-IL process on the desktop using **window hooks/DLL injection** or other same-IL primitives to fully compromise the admin context.<sup>[[1]](#references)</sup>

## Enumerating candidate writable paths
Run the PowerShell helper to discover writable/overwritable objects inside nominally secure roots from the perspective of a chosen token:<sup>[[1]](#references)</sup>

```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
  -DirectoryAccess AddFile -Recurse -ProcessId <PID>
```

- Run as Administrator for broader visibility; set `-ProcessId` to a low-priv process to mirror that token’s access.
- Filter manually to exclude known disallowed subdirectories before using candidates with `RAiLaunchAdminProcess`.

## Related

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess applications](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)

{{#include ../../banners/hacktricks-training.md}}
