# SeManageVolumePrivilege: Raw volume access for arbitrary file read

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows user right: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Holders can perform low-level volume operations such as defragmentation, creating/removing volumes, and maintenance IO. Critically for attackers, this right allows opening raw volume device handles (e.g., \\.\C:) and issuing direct disk I/O that bypasses NTFS file ACLs. With raw access you can copy bytes of any file on the volume even if denied by DACL, by parsing the filesystem structures offline or leveraging tools that read at the block/cluster level.

Default: Administrators on servers and domain controllers.

## Abuse scenarios

- Arbitrary file read bypassing ACLs by reading the disk device (e.g., exfiltrate sensitive system-protected material such as machine private keys under %ProgramData%\Microsoft\Crypto\RSA\MachineKeys and %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, etc.).
- Bypass locked/privileged paths (C:\Windows\System32\…) by copying bytes directly from the raw device.
- In AD CS environments, exfiltrate the CA’s key material (machine key store) to mint “Golden Certificates” and impersonate any domain principal via PKINIT. See link below.

Note: You still need a parser for NTFS structures unless you rely on helper tools. Many off-the-shelf tools abstract the raw access.

## Practical techniques

- Open a raw volume handle and read clusters:

<details>
<summary>Click to expand</summary>

```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
  static void Main(string[] a){
    using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
      fs.Position = 0x100000; // seek
      var buf = new byte[4096];
      fs.Read(buf,0,buf.Length);
      File.WriteAllBytes("C:\\temp\\blk.bin", buf);
    }
  }
}
```

</details>

- Use an NTFS-aware tool to recover specific files from raw volume:
  - RawCopy/RawCopy64 (sector-level copy of in-use files)
  - FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
  - vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

If you can read the Enterprise CA’s private key from the machine key store, you can forge client‑auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate. See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- Strongly limit assignment of SeManageVolumePrivilege (Perform volume maintenance tasks) to only trusted admins.
- Monitor Sensitive Privilege Use and process handle opens to device objects like \\.\C:, \\.\PhysicalDrive0.
- Prefer HSM/TPM-backed CA keys or DPAPI-NG so that raw file reads cannot recover key material in usable form.
- Keep uploads, temp, and extraction paths non-executable and separated (web context defense that often pairs with this chain post‑exploitation).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}