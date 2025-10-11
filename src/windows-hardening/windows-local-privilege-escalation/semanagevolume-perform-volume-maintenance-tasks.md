# SeManageVolumePrivilege: कच्चे वॉल्यूम एक्सेस के जरिए किसी भी फ़ाइल को पढ़ना

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Windows उपयोगकर्ता अधिकार: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

धारक low-level वॉल्यूम ऑपरेशंस कर सकते हैं जैसे defragmentation, वॉल्यूम बनाना/हटाना, और मेंटेनेंस IO. हमला करने वालों के लिए महत्वपूर्ण बात यह है कि यह अधिकार raw volume device handles (उदा., \\.\C:) खोलने और डायरेक्ट डिस्क I/O जारी करने की अनुमति देता है जो NTFS फ़ाइल ACLs को बायपास करता है। कच्चे एक्सेस के साथ आप वॉल्यूम पर किसी भी फ़ाइल के बाइट्स को कॉपी कर सकते हैं, भले ही DACL द्वारा मना किया गया हो, फाइल सिस्टम स्ट्रक्चर्स को ऑफ़लाइन पार्स करके या उन टूल्स का उपयोग करके जो ब्लॉक/क्लस्टर लेवल पर पढ़ते हैं।

डिफ़ॉल्ट: सर्वर और डोमेन कंट्रोलर पर Administrators।

## दुरुपयोग परिदृश्य

- डिस्क डिवाइस पढ़कर ACLs को बायपास करते हुए मनमाना फ़ाइल पढ़ना (उदा., संवेदनशील सिस्टम-प्रोटेक्टेड सामग्री जैसे %ProgramData%\Microsoft\Crypto\RSA\MachineKeys और %ProgramData%\Microsoft\Crypto\Keys के अंतर्गत मशीन प्राइवेट कीज़, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, आदि को exfiltrate करना)।
- लॉक किए गए/विशेषाधिकार वाले पाथ्स (C:\Windows\System32\…) को बायपास करना, कच्चे डिवाइस से बाइट्स सीधे कॉपी करके।
- AD CS वातावरणों में, CA की key material (machine key store) को exfiltrate करके “Golden Certificates” बनाना और PKINIT के माध्यम से किसी भी डोमेन प्रिंसिपल की नकल करना। नीचे लिंक देखें।

नोट: जब तक आप helper tools पर निर्भर नहीं करते, NTFS स्ट्रक्चर्स के लिए आपको अभी भी एक parser की ज़रूरत होगी। कई off-the-shelf टूल्स raw access को abstract करते हैं।

## व्यावहारिक तकनीकें

- raw volume handle खोलें और clusters पढ़ें:

<details>
<summary>विस्तार के लिए क्लिक करें</summary>
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

- कच्चे वॉल्यूम से विशिष्ट फ़ाइलें पुनर्प्राप्त करने के लिए NTFS-aware टूल का उपयोग करें:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, फिर snapshot से target फ़ाइल कॉपी करें (यदि आप VSS बना सकते हैं; अक्सर admin की आवश्यकता होती है लेकिन आमतौर पर वही ऑपरेटर उपलब्ध होते हैं जिनके पास SeManageVolumePrivilege होता है)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

यदि आप machine key store से Enterprise CA की private key पढ़ सकते हैं, तो आप arbitrary principals के लिए client‑auth certificates forge कर सकते हैं और PKINIT/Schannel के माध्यम से authenticate कर सकते हैं। इसे अक्सर Golden Certificate कहा जाता है। देखें:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(अनुभाग: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) को केवल भरोसेमंद admins तक ही सख्ती से सीमित करें।
- Sensitive Privilege Use और device objects जैसे \\.\C:, \\.\PhysicalDrive0 के लिए process handle opens की निगरानी करें।
- HSM/TPM-backed CA keys या DPAPI-NG पसंद करें ताकि raw file reads से key material उपयोगयोग्य रूप में पुनर्प्राप्त न हो सके।
- uploads, temp, और extraction paths को non-executable रखें और अलग रखें (web context defense जो अक्सर इस chain के post‑exploitation के साथ जुड़ती है)।

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
