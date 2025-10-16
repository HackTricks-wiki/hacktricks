# SeManageVolumePrivilege: Ufikiaji wa volumu ghafi kwa kusoma faili yoyote

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Haki ya mtumiaji ya Windows: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Wanaoshikilia haki hii wanaweza kufanya shughuli za chini za volumu kama defragmentation, kuunda/kuondoa volumu, na matengenezo ya I/O. Muhimu kwa wadukuzi, haki hii inaruhusu kufungua raw volume device handles (mfano, \\.\C:) na kutoa disk I/O ya moja kwa moja inayopitisha NTFS file ACLs. Kwa ufikiaji ghafi unaweza kunakili byte za faili yoyote kwenye volumu hata kama DACL inakataza, kwa kuchanganua miundo ya filesystem nje ya mtandao (offline) au kwa kutumia zana zinazosomea kwa ngazi ya block/cluster.

Chaguo-msingi: Administrators kwenye servers na domain controllers.

## Mifano ya matumizi mabaya

- Kusoma faili kwa hiari bila kuzingatia ACLs kwa kusoma kifaa cha disk (mfano, ku-exfiltrate nyenzo nyeti zilizo chini ya ulinzi wa mfumo kama private keys za mashine chini ya %ProgramData%\Microsoft\Crypto\RSA\MachineKeys na %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit kupitia VSS, n.k.).
- Kupitisha njia zilizofungwa/zinazopewa kipengele maalum (C:\Windows\System32\…) kwa kunakili byte moja kwa moja kutoka kwenye kifaa ghafi.
- Katika mazingira ya AD CS, ku-exfiltrate nyenzo za kiufunguo za CA (machine key store) ili kutengeneza “Golden Certificates” na kuiga yoyote domain principal kupitia PKINIT. Tazama kiungo hapo chini.

Kumbuka: Bado unahitaji parser wa miundo ya NTFS isipokuwa ukitegemea zana za msaada. Zana nyingi za off-the-shelf zinaficha ufikiaji ghafi.

## Mbinu za vitendo

- Fungua handle ya volumu ghafi na usome clusters:

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

- Tumia zana inayojua NTFS kurejesha faili maalum kutoka kwenye volume ghafi:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (kuunda picha kwa read-only, kisha kuchimba faili)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Ikiwa unaweza kusoma ufunguo wa faragha wa Enterprise CA kutoka kwenye machine key store, unaweza kuunda vyeti vya client‑auth kwa wadhamini wowote na kuthibitisha kupitia PKINIT/Schannel. Hii mara nyingi huitwa Golden Certificate. Angalia:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Utambuzi na kuimarisha

- Punguza kwa kiasi kikubwa utoaji wa SeManageVolumePrivilege (Perform volume maintenance tasks) kwa wasimamizi walioaminika tu.
- Fuatilia Sensitive Privilege Use na ufunguzi wa handles za mchakato kwa vitu vya kifaa kama \\.\C:, \\.\PhysicalDrive0.
- Pendelea ufunguo za CA zinazotegemea HSM/TPM au DPAPI-NG ili kusoma faili ghafi kusiweze kurejesha nyenzo za ufunguo kwa namna inayoweza kutumika.
- Weka njia za uploads, temp, na extraction zisizotekelezeka na zilizo tengana (ulinzi katika muktadha wa wavuti unaoambatana mara nyingi na mnyororo huu baada ya post‑exploitation).

## Marejeo

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
