# SeManageVolumePrivilege: Volume-maintenance abuse and raw-access validation

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows user right: Volume maintenance tasks करना (constant: SeManageVolumePrivilege).

यह अधिकार defragmentation और volumes बनाने या हटाने जैसे volume-maintenance operations की अनुमति देता है। Microsoft चेतावनी देता है कि इसका holder ऐसी files को storage में extend कर सकता है जिसमें अन्य data मौजूद हो, और फिर प्राप्त bytes को read या modify कर सकता है।<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` का होना guaranteed raw-disk access के बराबर न मानें। Microsoft के अनुसार direct access के लिए `CreateFile` के माध्यम से physical disk या volume खोलने हेतु administrative privileges आवश्यक हैं, और सामान्य object/device access checks अभी भी लागू होते हैं। किसी particular build या product पर arbitrary file read का दावा करने से पहले जाँचें कि token, device ACL, requested access, share flags और volume state raw handle की अनुमति देते हैं या नहीं।<sup>[[3]](#references)</sup>

Default: servers और domain controllers पर Administrators।<sup>[[1]](#references)</sup>

## Abuse scenarios

- यदि account वास्तव में readable raw-volume handle प्राप्त कर सकता है, तो NTFS-aware parser per-file ACLs को bypass करके allocated clusters से protected या locked files recover कर सकता है।
- संभावित targets में `C:\Windows\System32` के अंतर्गत locked या ACL-protected content, registry hives, DPAPI master keys, SAM और—जहाँ snapshot या offline volume के माध्यम से अलग से access उपलब्ध हो—`ntds.dit` शामिल हैं।
- Certificate services hosts पर उपयोगी software-key locations में `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` और `%ProgramData%\Microsoft\Crypto\Keys` शामिल हैं; किसी file को recover करना तभी उपयोगी है जब उसका key material exportable हो और उसे decrypt भी किया जा सके।<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- AD CS host पर successfully recovered **exportable/software-backed** CA private key Golden Certificate abuse को सक्षम कर सकती है। Hardware-backed या non-exportable key designs इस path को बदल देते हैं।<sup>[[2]](#references)</sup>

Note: जब तक आप helper tools पर निर्भर न हों, आपको NTFS structures के लिए parser की आवश्यकता होगी। कई off-the-shelf tools raw access को abstract कर देते हैं।

## Practical techniques

- Raw volume handle खोलें और clusters read करें:

<details>
<summary>विस्तार करने के लिए क्लिक करें</summary>
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

- raw volume से specific files recover करने के लिए NTFS-aware tool का उपयोग करें:
- RawCopy/RawCopy64 (in-use files की sector-level copy)
- FTK Imager या The Sleuth Kit (read-only imaging, फिर files carve करें)
- vssadmin/diskshadow + shadow copy, फिर snapshot से target file copy करें (यदि आप VSS create कर सकते हैं; इसके लिए अक्सर admin की आवश्यकता होती है, लेकिन यह आमतौर पर उन्हीं operators के लिए उपलब्ध होता है जिनके पास SeManageVolumePrivilege होता है)

Target करने के लिए सामान्य sensitive paths:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – shadow copy के माध्यम से)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys ऊपर दिए गए machine key store में रहती हैं)

## AD CS tie‑in: Golden Certificate Forging

यदि आप machine key store से Enterprise CA की private key पढ़ सकते हैं, तो आप arbitrary principals के लिए client-auth certificates forge कर सकते हैं और PKINIT/Schannel के माध्यम से authenticate कर सकते हैं। इसे अक्सर Golden Certificate कहा जाता है।<sup>[[2]](#references)</sup> देखें:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Stolen CA Certificates के साथ Certificates Forge करना (Golden Certificate) – DPERSIST1”).

## Detection और hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) का assignment केवल trusted admins तक सख्ती से सीमित करें।
- Sensitive Privilege Use और \\.\C:, \\.\PhysicalDrive0 जैसे device objects के लिए process handle opens को monitor करें।
- Properly configured HSM- या TPM-backed, non-exportable CA keys को प्राथमिकता दें, ताकि copied key-container file usable private-key material recover करने के लिए पर्याप्त न हो।
- CA-key path के बाहर के application secrets के लिए DPAPI या DPAPI-NG copied data file को अपर्याप्त बना सकते हैं, क्योंकि वे इसे user, machine, group या किसी अन्य authorized principal से protect करते हैं। यह उस plaintext को protect नहीं करता जो compromised principal के लिए पहले से accessible हो।<sup>[[4]](#references)</sup>
- uploads, temp और extraction paths को non-executable और अलग रखें (web context defense, जो अक्सर इस chain post‑exploitation के साथ उपयोग किया जाता है)।

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (CA key पढ़ने के लिए SeManageVolumePrivilege का उपयोग → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
