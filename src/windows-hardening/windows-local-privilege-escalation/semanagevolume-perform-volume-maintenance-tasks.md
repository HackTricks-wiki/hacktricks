# SeManageVolumePrivilege: Raw volume access for arbitrary file read

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows-gebruikersreg: Perform volume maintenance tasks (konstante: SeManageVolumePrivilege).

Houers kan laevlak-volume-bewerkings uitvoer, soos defragmentering, die skep/verwydering van volumes en maintenance IO. Kritiek vir aanvallers is dat hierdie reg dit moontlik maak om raw volume device handles (bv. \\.\C:) oop te maak en direkte skyf-I/O uit te voer wat NTFS-lêer-ACL's omseil. Met raw access kan jy die grepe van enige lêer op die volume kopieer, selfs al word toegang deur 'n DACL geweier, deur die lêerstelselstrukture offline te ontleed of tools te gebruik wat op blok-/cluster-vlak lees.

Verstek: Administrators op servers en domain controllers.<sup>[[1]](#references)</sup>

## Misbruikscenario's

- Arbitrêre lêerlees wat ACL's omseil deur die skyftoestel te lees (bv. eksfiltreer sensitiewe stelselbeskermde materiaal soos machine private keys onder %ProgramData%\Microsoft\Crypto\RSA\MachineKeys en %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, ens.).
- Omseil locked/privileged paths (C:\Windows\System32\…) deur grepe direk vanaf die raw device te kopieer.
- In AD CS-omgewings, eksfiltreer die CA se key material (machine key store) om “Golden Certificates” te mint en enige domain principal via PKINIT na te boots. Sien die skakel hieronder.<sup>[[2]](#references)</sup>

Nota: Jy benodig steeds 'n parser vir NTFS-strukture, tensy jy op helper tools staatmaak. Baie off-the-shelf tools abstraheer die raw access.

## Praktiese tegnieke

- Maak 'n raw volume handle oop en lees clusters:

<details>
<summary>Klik om uit te brei</summary>
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

- Gebruik 'n NTFS-aware tool om spesifieke lêers vanaf die raw volume te herstel:
- RawCopy/RawCopy64 (sektorvlak-kopiëring van lêers wat in gebruik is)
- FTK Imager of The Sleuth Kit (leesalleen-imaging, waarna lêers gecarve kan word)
- vssadmin/diskshadow + shadow copy, en kopieer dan die teikenlêer vanaf die snapshot (indien jy VSS kan skep; dit vereis dikwels admin-regte, maar is algemeen beskikbaar vir dieselfde operators wat SeManageVolumePrivilege het)

Tipiese sensitiewe paths om te teiken:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certificates/CRLs; private keys word in die machine key store hierbo gestoor)

## AD CS-koppeling: Forging a Golden Certificate

As jy die Enterprise CA se private key vanaf die machine key store kan lees, kan jy client-auth certificates vir arbitrêre principals forgeer en via PKINIT/Schannel authenticate. Daar word dikwels hierna verwys as 'n Golden Certificate.<sup>[[2]](#references)</sup> Sien:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection en hardening

- Beperk die toewysing van SeManageVolumePrivilege (Perform volume maintenance tasks) streng tot slegs trusted admins.
- Monitor Sensitive Privilege Use en process handle opens na device objects soos \\.\C:, \\.\PhysicalDrive0.
- Verkies HSM/TPM-backed CA keys of DPAPI-NG sodat raw file reads nie key material in bruikbare vorm kan herwin nie.
- Hou uploads, temp- en extraction paths nie-uitvoerbaar en geskei (web context defense wat dikwels met hierdie post-exploitation chain saamgaan).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
