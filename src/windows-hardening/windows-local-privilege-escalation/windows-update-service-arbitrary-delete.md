# Windows Update Service Arbitrary Delete (CVE-2025-48799)
{{#include /banners/hacktricks-training.md}}



## Overview

CVE-2025-48799 is a local elevation-of-privilege vulnerability in the Windows Update service (`wuauserv`) on Windows 10/11 systems with two or more physical drives. By abusing an undocumented API and race conditions, an attacker can abuse the service's cleanup routine to perform an arbitrary folder delete as SYSTEM.

## Attack Flow

1. **Storage Sense Redirection Abuse**
   - Call the undocumented `SetStorageSettings` API to redirect UWP app installations to a secondary (attacker-controlled) volume.
2. **Watch for Cache Creation & Symlink**
   - Monitor `WUDownloadCache` directory creation.
   - Upon detection, create a DOS device symlink in the `\RPC Control` namespace pointing `\RPC Control\Config.msi` → `C:\Config.msi`.
3. **Trigger Cleanup via Winget**
   - Execute `winget install <any-app>` to invoke Windows Update service cleanup path (`CleanupWUCacheFolders`).
4. **Oplock & Mount-Point Race**
   - Set an opportunistic lock (oplock) on the cache folder or files to pause deletion.
   - Inside the oplock callback, convert the folder into a mount-point junction targeting `\RPC Control`, so further delete calls remove `C:\Config.msi`.
5. **SYSTEM Deletes Protected File**
   - The service cleanup deletes the DOS device stream of `Config.msi`, causing NTFS to delete the `C:\Config.msi` file as SYSTEM.
6. **Payload Execution**
   - Place a malicious file at `C:\Config.msi` (a renamed DLL or EXE), then launch an auto-elevated binary that loads it (e.g., `osk.exe`).
   - Achieve arbitrary code execution as SYSTEM.

## Key Components

- **Service:** wuauserv (Windows Update)
- **Undocumented API:** SetStorageSettings in Storage Sense
- **Cache Folder:** `%ProgramData%\Microsoft\Windows\WUDownloadCache`
- **Trigger Command:** winget install
- **Symlink Namespace:** `\RPC Control` DOS device
- **Race Primitives:** Oplock + mount-point junction

## Prerequisites

- Windows 10/11 with at least two physical drives.
- Local user privileges and ability to call `SetStorageSettings` or equivalent.

## PoC Steps (High-Level)

```c
// 1. Redirect to attacker drive
HRESULT hr = SetStorageSettings(...);

// 2. Start watcher for WUDownloadCache
CreateDirectoryWatcher(..., L"WUDownloadCache");

// 3. On creation, create symlink
DefineDosDevice(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                L"\\RPC Control\\Config.msi",
                L"C:\\Config.msi");

// 4. Trigger winget install
system("winget install Microsoft.Notepad");

// 5. Use oplock and junction in callback
//    - RequestOplock on a cache file
//    - When paused, call CreateSymbolicLink or CreateMountPoint to switch

// 6. Place malicious payload and execute via osk.exe
```

## Mitigation & Detection

- Apply Microsoft patch for CVE-2025-48799.
- Restrict use of undocumented `SetStorageSettings` APIs (if possible).
- Monitor abnormal DOS device creations under `\\RPC Control`.
- Audit wingset invocations and arbitrary deletes in `%SystemRoot%`.

## References

- [CVE-2025-48799 Windows Update Service PoC](https://github.com/Wh04m1001/CVE-2025-48799/)
- [Abusing Arbitrary File Deletes to Escalate Privilege (ZDI Blog)](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
{{#include /banners/hacktricks-training.md}}
