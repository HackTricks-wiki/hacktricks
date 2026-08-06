# SeManageVolumePrivilege: Ufikiaji wa raw volume kwa kusoma faili kiholela

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Haki ya mtumiaji ya Windows: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Wenye haki hii wanaweza kufanya shughuli za kiwango cha chini kwenye volume, kama vile defragmentation, kuunda/kuondoa volumes, na maintenance IO. Muhimu kwa attackers, haki hii inaruhusu kufungua raw volume device handles (kwa mfano, \\.\C:) na kutoa direct disk I/O inayopita NTFS file ACLs. Kwa raw access, unaweza kunakili bytes za faili lolote kwenye volume hata kama DACL inakuzuia, kwa kuchanganua miundo ya filesystem offline au kutumia tools zinazosoma katika kiwango cha block/cluster.

Default: Administrators kwenye servers na domain controllers.<sup>[[1]](#references)</sup>

## Matukio ya abuse

- Kusoma faili kiholela kwa kupita ACLs kwa kusoma disk device (kwa mfano, ku-exfiltrate taarifa nyeti zinazolindwa na mfumo kama machine private keys zilizo chini ya %ProgramData%\Microsoft\Crypto\RSA\MachineKeys na %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit kupitia VSS, n.k.).
- Kupita locked/privileged paths (C:\Windows\System32\…) kwa kunakili bytes moja kwa moja kutoka kwenye raw device.
- Katika mazingira ya AD CS, ku-exfiltrate CA’s key material (machine key store) ili kutengeneza “Golden Certificates” na kujifanya domain principal yoyote kupitia PKINIT. Tazama link hapa chini.<sup>[[2]](#references)</sup>

Kumbuka: Bado unahitaji parser ya miundo ya NTFS isipokuwa utegemee helper tools. Tools nyingi zinazopatikana tayari huficha raw access.

## Mbinu za vitendo

- Fungua raw volume handle na usome clusters:

<details>
<summary>Bofya ili kupanua</summary>
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

- Tumia tool inayotambua NTFS kurejesha faili mahususi kutoka kwenye raw volume:
- RawCopy/RawCopy64 (sector-level copy ya faili zinazotumika)
- FTK Imager au The Sleuth Kit (read-only imaging, kisha carve files)
- vssadmin/diskshadow + shadow copy, kisha nakili faili lengwa kutoka kwenye snapshot (ikiwa unaweza kuunda VSS; mara nyingi huhitaji admin, lakini kwa kawaida hupatikana kwa operators wale wale walio na SeManageVolumePrivilege)

Njia nyeti za kawaida za kulenga:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – kupitia shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys huhifadhiwa kwenye machine key store iliyo hapo juu)

## Muunganiko wa AD CS: Forging a Golden Certificate

Ikiwa unaweza kusoma private key ya Enterprise CA kutoka kwenye machine key store, unaweza kutengeneza client-auth certificates za principals wowote na ku-authenticate kupitia PKINIT/Schannel. Hii mara nyingi huitwa Golden Certificate.<sup>[[2]](#references)</sup> Tazama:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sehemu: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Utambuzi na hardening

- Punguza kwa ukali ugawaji wa SeManageVolumePrivilege (Perform volume maintenance tasks) kwa admins wanaoaminika pekee.
- Fuatilia Sensitive Privilege Use na process handle opens kwa device objects kama \\.\C:, \\.\PhysicalDrive0.
- Pendelea CA keys zinazoungwa mkono na HSM/TPM au DPAPI-NG ili raw file reads zisiweze kurejesha key material katika mfumo unaoweza kutumika.
- Weka uploads, temp, na extraction paths zikiwa non-executable na zimetenganishwa (web context defense ambayo mara nyingi huambatana na chain hii ya post-exploitation).

## Marejeo

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
