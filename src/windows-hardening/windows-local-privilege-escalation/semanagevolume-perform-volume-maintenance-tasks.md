# SeManageVolumePrivilege: किसी भी फ़ाइल को पढ़ने के लिए कच्चे वॉल्यूम एक्सेस

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Windows उपयोगकर्ता अधिकार: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

इस अधिकार के धारक low-level वॉल्यूम ऑपरेशंस कर सकते हैं जैसे कि defragmentation, वॉल्यूम बनाना/हटाना, और मेंटेनेंस I/O। हमलावरों के लिए महत्वपूर्ण बात यह है कि यह अधिकार कच्चे वॉल्यूम डिवाइस हैंडल (उदाहरण: \\.\C:) खोलने और ऐसा डायरेक्ट डिस्क I/O करने की अनुमति देता है जो NTFS फ़ाइल ACLs को बायपास करता है। कच्चे एक्सेस के साथ आप वॉल्यूम पर किसी भी फ़ाइल के बाइट्स कॉपी कर सकते हैं भले ही DACL द्वारा इनकार किया गया हो — यह फ़ाइल सिस्टम स्ट्रक्चर्स को ऑफ़लाइन पार्स करके या ब्लॉक/क्लस्टर स्तर पर पढ़ने वाले टूल्स का उपयोग करके संभव है।

डिफ़ॉल्ट: सर्वरों और डोमेन कंट्रोलर्स पर Administrators.

## दुरुपयोग परिदृश्य

- डिस्क डिवाइस पढ़कर ACLs को बायपास करके किसी भी फ़ाइल को पढ़ना/निकासी (उदा., संवेदनशील सिस्टम-प्रोटेक्टेड सामग्री जैसे %ProgramData%\Microsoft\Crypto\RSA\MachineKeys और %ProgramData%\Microsoft\Crypto\Keys के तहत मशीन प्राइवेट कीज़, registry hives, DPAPI masterkeys, SAM, ntds.dit (VSS के माध्यम से) आदि)।
- लॉक्ड/प्रिविलेज्ड पाथ्स (C:\Windows\System32\…) को कच्चे डिवाइस से सीधे बाइट्स कॉपी करके बायपास करना।
- AD CS परिवेशों में, CA के की मटेरियल (machine key store) को एक्सफ़िल्ट्रेट करके “Golden Certificates” बनाना और PKINIT के जरिए किसी भी डोमेन प्रिंसिपल का impersonate करना। नीचे लिंक देखें।

नोट: जब तक आप helper tools पर भरोसा नहीं करते, आपको NTFS संरचनाओं के लिए एक पार्सर की आवश्यकता होगी। कई रेडी-टू-यूज़ टूल्स कच्चे एक्सेस को abstract कर देते हैं।

## व्यावहारिक तकनीकें

- कच्चा वॉल्यूम हैंडल खोलें और क्लस्टर्स पढ़ें:

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

- NTFS-aware टूल का उपयोग करके raw volume से विशिष्ट फ़ाइलें पुनर्प्राप्त करें:
- RawCopy/RawCopy64 (in-use फ़ाइलों की sector-स्तरीय कॉपी)
- FTK Imager or The Sleuth Kit (read-only imaging, फिर फ़ाइलें carve करें)
- vssadmin/diskshadow + shadow copy, फिर snapshot से target फ़ाइल कॉपी करें (यदि आप VSS बना सकते हैं; अक्सर admin की आवश्यकता होती है पर आम तौर पर वही ऑपरेटर्स जिनके पास SeManageVolumePrivilege होता है इनके पास उपलब्ध होता है)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS संबंध: Forging a Golden Certificate

यदि आप machine key store से Enterprise CA की private key पढ़ सकते हैं, तो आप arbitrary principals के लिए client‑auth certificates forge कर सकते हैं और PKINIT/Schannel के माध्यम से authenticate कर सकते हैं। इसे अक्सर Golden Certificate कहा जाता है। देखें:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## पहचान और हार्डनिंग

- Strongly limit assignment of SeManageVolumePrivilege (Perform volume maintenance tasks) to only trusted admins.
- Monitor Sensitive Privilege Use और process handle opens to device objects जैसे \\.\C:, \\.\PhysicalDrive0 को मॉनिटर करें।
- HSM/TPM-backed CA keys या DPAPI-NG को प्राथमिकता दें ताकि raw file reads से key material usable रूप में recover न हो सके।
- अपलोड, temp, और extraction paths को non-executable और अलग रखें (web context defense जो अक्सर इस chain post‑exploitation के साथ जुड़ती है).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
