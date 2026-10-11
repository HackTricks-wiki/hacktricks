# SeManageVolumePrivilege: Volume-maintenance का दुरुपयोग और raw-access सत्यापन

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Windows user right: Volume maintenance tasks करना (constant: SeManageVolumePrivilege)।

यह अधिकार defragmentation और volumes बनाने या हटाने जैसे volume-maintenance operations की अनुमति देता है। Microsoft चेतावनी देता है कि इस अधिकार वाले व्यक्ति files को ऐसे storage तक बढ़ा सकते हैं जिसमें अन्य data हो, और फिर प्राप्त bytes को पढ़ या संशोधित कर सकते हैं।<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` का होना guaranteed raw-disk access के बराबर न मानें। Microsoft के अनुसार, direct access के लिए `CreateFile` के ज़रिए physical disk या volume खोलने हेतु administrative privileges आवश्यक हैं, और सामान्य object/device access checks भी लागू होते हैं। किसी विशेष build या product पर arbitrary file read का दावा करने से पहले जाँचें कि token, device ACL, requested access, share flags और volume state raw handle की अनुमति देते हैं या नहीं।<sup>[[3]](#references)</sup>

Default: Servers और domain controllers पर Administrators।<sup>[[1]](#references)</sup>

## दुरुपयोग के परिदृश्य

- यदि account वास्तव में readable raw-volume handle प्राप्त कर सकता है, तो NTFS-aware parser per-file ACLs को bypass करके allocated clusters से protected या locked files पुनर्प्राप्त कर सकता है।
- संभावित targets में `C:\Windows\System32` के अंतर्गत locked या ACL-protected content, registry hives, DPAPI master keys, SAM और—जहाँ snapshot या offline volume के माध्यम से अलग से पहुँचा जा सकता हो—`ntds.dit` शामिल हैं।
- Certificate services hosts पर, उपयोगी software-key locations में `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` और `%ProgramData%\Microsoft\Crypto\Keys` शामिल हैं; file पुनर्प्राप्त करना तभी उपयोगी है जब उसका key material exportable हो और उसे decrypt भी किया जा सके।<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- AD CS host पर, सफलतापूर्वक पुनर्प्राप्त **exportable/software-backed** CA private key से Golden Certificate का दुरुपयोग संभव हो सकता है। Hardware-backed या non-exportable key designs इस रास्ते को बदल देते हैं।<sup>[[2]](#references)</sup>
- कुछ volume-maintenance tools, अनुमति मिलने पर filesystem ACL entries को बदलने के लिए `FSCTL_SD_GLOBAL_CHANGE` का उपयोग करते हैं। इससे raw blocks को निष्क्रिय रूप से पढ़ने के बजाय access controls बदलते हैं; इसका असर volume के बड़े हिस्से पर हो सकता है, और इसे वास्तविक token तथा device behavior के अनुसार सत्यापित करना चाहिए। [Tool source](https://github.com/CsEnox/SeManageVolumeExploit) में यह विशिष्ट mechanism दिखाया गया है; केवल इस privilege का होना इसकी सफलता साबित नहीं करता।
- ACL changes के ज़रिए file access मिलने से EFS-encrypted file decrypt नहीं होती। Plaintext पाने के लिए अब भी matching user या recovery private key चाहिए। इसी तरह, software-backed CA key को [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) से export करना इस पर निर्भर करता है कि key स्थानीय रूप से उपलब्ध, exportable और accessible हो।

ध्यान दें: जब तक helper tools पर निर्भर न हों, आपको NTFS structures के लिए parser की आवश्यकता होगी। कई off-the-shelf tools raw access की जटिलता को छिपा देते हैं।

## व्यावहारिक तकनीकें

- Raw volume handle खोलें और clusters पढ़ें:

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

- raw volume से specific files recover करने के लिए NTFS-aware tool इस्तेमाल करें:
  - RawCopy/RawCopy64 (in-use files की sector-level copy)
  - FTK Imager या The Sleuth Kit (read-only imaging, फिर files carve करें)
  - vssadmin/diskshadow + shadow copy, फिर snapshot से target file copy करें (अगर आप VSS बना सकते हैं; इसके लिए अक्सर admin access चाहिए, लेकिन आम तौर पर यह उन operators के पास होता है जिनके पास SeManageVolumePrivilege है)

Target करने के लिए आम sensitive paths:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – shadow copy के ज़रिए)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys ऊपर दिए गए machine key store में होते हैं)

## AD CS से जुड़ाव: Golden Certificate forge करना

अगर आप machine key store से Enterprise CA की private key पढ़ सकते हैं, तो arbitrary principals के लिए client-auth certificates forge करके PKINIT/Schannel के ज़रिए authenticate कर सकते हैं। इसे अक्सर Golden Certificate कहा जाता है।<sup>[[2]](#references)</sup> देखें:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection और hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) का assignment सख्ती से सीमित करके केवल trusted admins को दें।
- Sensitive Privilege Use और \\.\C:, \\.\PhysicalDrive0 जैसे device objects पर process handle opens की निगरानी करें।
- ठीक से configured HSM- या TPM-backed, non-exportable CA keys को प्राथमिकता दें, ताकि copied key-container file से usable private-key material recover करना पर्याप्त न हो।
- CA-key path के बाहर application secrets के लिए, DPAPI या DPAPI-NG किसी copied data file को user, machine, group या किसी अन्य authorized principal से सुरक्षित करके उसे अपर्याप्त बना सकते हैं। इससे compromised principal को पहले से accessible plaintext सुरक्षित नहीं होता।<sup>[[4]](#references)</sup>
- Uploads, temp और extraction paths को non-executable और अलग रखें (web context defense, जो अक्सर इस post-exploitation chain के साथ इस्तेमाल होती है)।

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
