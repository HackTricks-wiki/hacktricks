# SeManageVolumePrivilege: Volume-maintenance abuse and raw-access validation

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows user right: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

The right authorizes volume-maintenance operations such as defragmentation and creating or removing volumes. Microsoft warns that a holder may be able to extend files into storage containing other data and then read or modify the acquired bytes.<sup>[[1]](#references)</sup>

Do not equate possession of `SeManageVolumePrivilege` with guaranteed raw-disk access. Microsoft documents that opening a physical disk or volume through `CreateFile` for direct access requires administrative privileges, and normal object/device access checks still apply. On a particular build or product, test whether the token, device ACL, requested access, share flags, and volume state permit a raw handle before claiming arbitrary file read.<sup>[[3]](#references)</sup>

Default: Administrators on servers and domain controllers.<sup>[[1]](#references)</sup>

## Abuse scenarios

- If the account can actually obtain a readable raw-volume handle, an NTFS-aware parser can bypass per-file ACLs and recover protected or locked files from allocated clusters.
- Possible targets include locked or ACL-protected content under `C:\Windows\System32`, registry hives, DPAPI master keys, the SAM, and—where separately accessible through a snapshot or offline volume—`ntds.dit`.
- On certificate services hosts, useful software-key locations include `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` and `%ProgramData%\Microsoft\Crypto\Keys`; recovering a file is useful only when its key material is exportable and can also be decrypted.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- On an AD CS host, a successfully recovered **exportable/software-backed** CA private key can enable Golden Certificate abuse. Hardware-backed or non-exportable key designs change this path.<sup>[[2]](#references)</sup>

Note: You still need a parser for NTFS structures unless you rely on helper tools. Many off-the-shelf tools abstract the raw access.

## Practical techniques

- Open a raw volume handle and read clusters:

<details>
<summary>Click to expand</summary>

```powershell
# Validation attempt: current Windows versions normally require an administrative token
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

If you can read the Enterprise CA’s private key from the machine key store, you can forge client‑auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate.<sup>[[2]](#references)</sup> See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- Strongly limit assignment of SeManageVolumePrivilege (Perform volume maintenance tasks) to only trusted admins.
- Monitor Sensitive Privilege Use and process handle opens to device objects like \\.\C:, \\.\PhysicalDrive0.
- Prefer properly configured HSM- or TPM-backed, non-exportable CA keys so a copied key-container file is not sufficient to recover usable private-key material.
- For application secrets outside the CA-key path, DPAPI or DPAPI-NG can make a copied data file insufficient by protecting it to a user, machine, group, or other authorized principal. This does not protect plaintext already accessible to the compromised principal.<sup>[[4]](#references)</sup>
- Keep uploads, temp, and extraction paths non-executable and separated (web context defense that often pairs with this chain post‑exploitation).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)

{{#include ../../banners/hacktricks-training.md}}
