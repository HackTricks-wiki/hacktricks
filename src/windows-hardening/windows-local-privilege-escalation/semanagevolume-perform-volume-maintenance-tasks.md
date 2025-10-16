# SeManageVolumePrivilege: Ruwe volume-toegang vir arbitrêre lêerlees

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows gebruikersreg: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Houers kan laevlak-volume-bewerkings uitvoer soos defragmentasie, skep/verwyder van volumes, en maintenance IO. Belangrik vir aanvallers: hierdie reg laat toe om ruwe volume-toestelhandvatsels te open (bv. \\.\C:) en direkte disk I/O uit te voer wat NTFS file ACLs omseil. Met ruwe toegang kan jy bytes van enige lêer op die volume kopieer selfs al word toegang deur die DACL geweier, deur die lêerstelselstrukture offline te ontleed of hulpmiddele te gebruik wat op blok-/clustervlak lees.

Standaard: Administrators on servers and domain controllers.

## Misbruikscenario's

- Arbitrêre lêerlees wat ACLs omseil deur die skyftoestel te lees (bv. exfiltrate sensitiewe stelselsbeskermde materiaal soos machine private keys onder %ProgramData%\Microsoft\Crypto\RSA\MachineKeys en %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, ens.).
- Omseil geslote/geprivilegieerde paaie (C:\Windows\System32\…) deur bytes direk vanaf die ruwe toestel te kopieer.
- In AD CS omgewings, exfiltrate die CA’s key material (machine key store) om “Golden Certificates” te mint en enige domain principal te impersonate via PKINIT. Sien link hieronder.

Let wel: Jy benodig steeds 'n parser vir NTFS-strukture tensy jy op helper tools staatmaak. Baie kant-en-klare tools abstraheer die ruwe toegang.

## Praktiese tegnieke

- Open a raw volume handle and read clusters:

<details>
<summary>Klik om uit te vou</summary>
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

- Gebruik 'n NTFS-bewuste tool om spesifieke lêers van 'n rou volume te herstel:
- RawCopy/RawCopy64 (sektorvlak-kopie van in‑gebruik-lêers)
- FTK Imager of The Sleuth Kit (lees-alleen imaging, dan carve files)
- vssadmin/diskshadow + shadow copy, dan kopieer die teikenlêer vanaf die snapshot (as jy VSS kan skep; vereis dikwels admin maar is gewoonlik beskikbaar vir dieselfde operateurs wat SeManageVolumePrivilege het)

Tipiese sensitiewe paaie om teiken:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (lokale geheime)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys leef in die machine key store hierbo)

## AD CS tie‑in: Forging a Golden Certificate

As jy die Enterprise CA se private sleutel uit die machine key store kan lees, kan jy client‑auth certificates vir arbitrêre principals forge en verifieer via PKINIT/Schannel. Dit word dikwels verwys na as 'n Golden Certificate. Sien:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Afdeling: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- Beperk sterk die toekenning van SeManageVolumePrivilege (Perform volume maintenance tasks) slegs aan betroubare admins.
- Monitor Sensitive Privilege Use en proses-handle-openings na device objects soos \\.\C:, \\.\PhysicalDrive0.
- Bied voorkeur aan HSM/TPM-backed CA keys of DPAPI-NG sodat rou lêerslees nie sleutelmateriaal in bruikbare vorm kan herstel nie.
- Hou uploads-, temp- en ekstraksiepaaie nie-uitvoerbaar en geskei (web‑konteks verdediging wat dikwels saam met hierdie ketting post‑exploitation gepaard gaan).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
