# SeManageVolumePrivilege: मनमानी फ़ाइल read के लिए Raw volume access

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows user right: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

इसके धारक low-level volume operations, जैसे defragmentation, volumes को create/remove करना और maintenance IO, कर सकते हैं। Attackers के लिए महत्वपूर्ण रूप से, यह right raw volume device handles (जैसे, \\.\C:) खोलने और direct disk I/O जारी करने की अनुमति देता है, जो NTFS file ACLs को bypass करता है। Raw access के साथ आप volume पर मौजूद किसी भी फ़ाइल के bytes को copy कर सकते हैं, भले ही DACL द्वारा access denied हो, filesystem structures को offline parse करके या block/cluster level पर read करने वाले tools का उपयोग करके।

Default: servers और domain controllers पर Administrators.<sup>[[1]](#references)</sup>

## Abuse scenarios

- Disk device को read करके ACLs को bypass करते हुए arbitrary file read (जैसे %ProgramData%\Microsoft\Crypto\RSA\MachineKeys और %ProgramData%\Microsoft\Crypto\Keys के अंतर्गत मौजूद sensitive system-protected material, registry hives, DPAPI masterkeys, SAM, VSS के माध्यम से ntds.dit आदि को exfiltrate करना)।
- Raw device से सीधे bytes copy करके locked/privileged paths (C:\Windows\System32\…) को bypass करना।
- AD CS environments में, CA के key material (machine key store) को exfiltrate करके “Golden Certificates” mint करना और PKINIT के माध्यम से किसी भी domain principal का impersonate करना। नीचे दिए गए link को देखें।<sup>[[2]](#references)</sup>

Note: जब तक आप helper tools पर निर्भर न हों, आपको NTFS structures के लिए parser की अभी भी आवश्यकता होगी। कई off-the-shelf tools raw access को abstract कर देते हैं।

## Practical techniques

- Raw volume handle खोलें और clusters read करें:

<details>
<summary>विस्तार करने के लिए क्लिक करें</summary>
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

- Raw volume से specific files recover करने के लिए NTFS-aware tool का उपयोग करें:
- RawCopy/RawCopy64 (in-use files की sector-level copy)
- FTK Imager या The Sleuth Kit (read-only imaging, फिर files को carve करें)
- vssadmin/diskshadow + shadow copy, फिर snapshot से target file copy करें (यदि आप VSS create कर सकते हैं; इसके लिए अक्सर admin privileges की आवश्यकता होती है, लेकिन ये privileges आमतौर पर उन्हीं operators के पास होते हैं जिनके पास SeManageVolumePrivilege होता है)

Target करने के लिए सामान्यतः sensitive paths:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – shadow copy के माध्यम से)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys ऊपर दिए गए machine key store में रहते हैं)

## AD CS tie‑in: Forging a Golden Certificate

यदि आप Enterprise CA की private key को machine key store से पढ़ सकते हैं, तो आप arbitrary principals के लिए client-auth certificates forge कर सकते हैं और PKINIT/Schannel के माध्यम से authenticate कर सकते हैं। इसे अक्सर Golden Certificate कहा जाता है।<sup>[[2]](#references)</sup> देखें:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) का assignment केवल trusted admins तक सख्ती से सीमित करें।
- Sensitive Privilege Use और \\.\C:, \\.\PhysicalDrive0 जैसे device objects के लिए process handle opens को monitor करें।
- HSM/TPM-backed CA keys या DPAPI-NG को प्राथमिकता दें, ताकि raw file reads से key material usable form में recover न किया जा सके।
- Uploads, temp और extraction paths को non-executable और अलग रखें (यह web context defense है, जो अक्सर इस post-exploitation chain के साथ उपयोग किया जाता है)।

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
