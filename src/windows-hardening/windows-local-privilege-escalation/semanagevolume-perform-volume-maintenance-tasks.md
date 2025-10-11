# SeManageVolumePrivilege: Ruwe volume-toegang vir arbitrêre lêerlees

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows gebruikersreg: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

Houers kan laagvlak volume-operasies uitvoer soos defragmentation, skep/verwyder volumes, en onderhouds-I/O. Krities vir aanvallers: hierdie reg laat toe om rou volume-toestel-handles oop te maak (bv. \\.\C:) en direkte skyf I/O uit te voer wat NTFS file ACLs omseil. Met rou toegang kan jy bytes van enige lêer op die volume kopieer selfs al is dit deur die DACL geweier, deur die filesystem-strukture offline te parse of hulpmiddels te gebruik wat op blok-/klustervlak lees.

Standaard: Administrateurs op bedieners en domeincontrollers.

## Misbruikscenario's

- Arbitrêre lêerlees wat ACLs omseil deur die skyf-toestel te lees (bv. eksfiltreer sensitiewe stelsel-beskermde materiaal soos masjien-private sleutels onder %ProgramData%\Microsoft\Crypto\RSA\MachineKeys en %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, ens.).
- Omseil geslote/geprivilegieerde paaie (C:\Windows\System32\…) deur bytes direk vanaf die rou toestel te kopieer.
- In AD CS omgewings, eksfiltreer die CA se sleutelmateriaal (machine key store) om “Golden Certificates” te mint en enige domein-prinsipaal te imiteer via PKINIT. Sien skakel hieronder.

Let wel: Jy het steeds 'n parser vir NTFS-strukture nodig tensy jy op helper-werktuie staatmaak. Baie kant-en-klare gereedskap abstraheer die rou toegang.

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

- Gebruik 'n NTFS-bewuste hulpmiddel om spesifieke lêers vanaf die rou volume te herstel:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, en kopieer dan die teikenlêer vanaf die snapshot (as jy VSS kan skep; vereis dikwels admin maar is gewoonlik beskikbaar vir dieselfde operateurs wat SeManageVolumePrivilege besit)

Tipiese sensitiewe paaie om te teiken:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS koppeling: Forging a Golden Certificate

As jy die Enterprise CA se private sleutel uit die machine key store kan lees, kan jy client‑auth certificates vir arbitrary principals vervals en verifieer via PKINIT/Schannel. Dit word dikwels 'n Golden Certificate genoem. Sien:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Afdeling: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Opsporing en verharding

- Beperk sterk die toewysing van SeManageVolumePrivilege (Perform volume maintenance tasks) slegs aan vertroude administrateurs.
- Monitor Sensitive Privilege Use en proses-handle-openings na toestelobjekte soos \\.\C:, \\.\PhysicalDrive0.
- Voorkeur vir HSM/TPM-ondersteunde CA-sleutels of DPAPI-NG sodat rou lêerlees nie sleutelmateriaal in bruikbare vorm kan herstel nie.
- Hou uploads-, temp- en uitpak-paaie nie-uitvoerbaar en geskei (web-konteks verdediging wat dikwels saam met hierdie ketting post‑exploitation gepaardgaan).

## Verwysings

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
